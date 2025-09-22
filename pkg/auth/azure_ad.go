package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

const (
	// JWKS cache TTL - refresh every 10 minutes
	jwksCacheTTL = 10 * time.Minute
)

type AzureADAuthSetter struct {
	additionalAuthScopes []v1.AuthScope
	cfg                  v1.AuthAzureADClientConfig
}

func NewAzureADAuthSetter(additionalAuthScopes []v1.AuthScope, cfg v1.AuthAzureADClientConfig) *AzureADAuthSetter {
	return &AzureADAuthSetter{
		additionalAuthScopes: additionalAuthScopes,
		cfg:                  cfg,
	}
}

func (as *AzureADAuthSetter) generateAccessToken() (accessToken string, err error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to initialize Azure credentials: %w", err)
	}

	scope := fmt.Sprintf("%s/.default", as.cfg.Audience)
	opts := policy.TokenRequestOptions{
		Scopes: []string{scope},
	}

	token, err := cred.GetToken(context.Background(), opts)
	if err != nil {
		return "", fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	return token.Token, nil
}

func (as *AzureADAuthSetter) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.PrivilegeKey, err = as.generateAccessToken()
	return err
}

func (as *AzureADAuthSetter) SetPing(pingMsg *msg.Ping) (err error) {
	if !slices.Contains(as.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}

	pingMsg.PrivilegeKey, err = as.generateAccessToken()
	return err
}

func (as *AzureADAuthSetter) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) (err error) {
	if !slices.Contains(as.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}

	newWorkConnMsg.PrivilegeKey, err = as.generateAccessToken()
	return err
}

// Claims represents the expected claims in an Azure AD JWT token
type Claims struct {
	Audience jwt.ClaimStrings `json:"aud"`
	Issuer   string           `json:"iss"`
	TenantID string           `json:"tid"`
	jwt.RegisteredClaims
}

type AzureADAuthVerifier struct {
	additionalAuthScopes []v1.AuthScope
	cfg                  v1.AuthAzureADServerConfig

	// JWKS cache
	jwksMutex   sync.RWMutex
	jwks        keyfunc.Keyfunc
	jwksExpires time.Time
}

func NewAzureADAuthVerifier(additionalAuthScopes []v1.AuthScope, cfg v1.AuthAzureADServerConfig) *AzureADAuthVerifier {
	return &AzureADAuthVerifier{
		additionalAuthScopes: additionalAuthScopes,
		cfg:                  cfg,
	}
}

// getJWKS returns cached JWKS or fetches fresh ones if cache is expired
func (av *AzureADAuthVerifier) getJWKS() (keyfunc.Keyfunc, error) {
	// Try to use cached JWKS first
	av.jwksMutex.RLock()
	if av.jwks != nil && time.Now().Before(av.jwksExpires) {
		jwks := av.jwks
		av.jwksMutex.RUnlock()
		return jwks, nil
	}
	av.jwksMutex.RUnlock()

	// Cache miss or expired, fetch new JWKS
	av.jwksMutex.Lock()
	defer av.jwksMutex.Unlock()

	// Double-check in case another goroutine fetched while we waited for lock
	if av.jwks != nil && time.Now().Before(av.jwksExpires) {
		return av.jwks, nil
	}

	jwksURL := "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS for token verification: %w", err)
	}

	// Cache the JWKS
	av.jwks = jwks
	av.jwksExpires = time.Now().Add(jwksCacheTTL)

	return jwks, nil
}

func (av *AzureADAuthVerifier) verifyToken(token string) error {
	// Get JWKS (from cache or fetch new)
	jwks, err := av.getJWKS()
	if err != nil {
		return err
	}

	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, jwks.Keyfunc)
	if err != nil {
		// Provide detailed error messages for common JWT issues
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "token is expired"):
			return fmt.Errorf("token validation failed: token has expired")
		case strings.Contains(errMsg, "token used before valid"):
			return fmt.Errorf("token validation failed: token is not valid yet")
		case strings.Contains(errMsg, "invalid audience"):
			return fmt.Errorf("token validation failed: invalid audience")
		case strings.Contains(errMsg, "invalid issuer"):
			return fmt.Errorf("token validation failed: invalid issuer")
		case strings.Contains(errMsg, "signature is invalid"):
			return fmt.Errorf("token validation failed: invalid signature")
		case strings.Contains(errMsg, "token is malformed"):
			return fmt.Errorf("token validation failed: token is malformed")
		default:
			return fmt.Errorf("error parsing or validating token: %w", err)
		}
	}
	if !parsedToken.Valid {
		return fmt.Errorf("token is invalid: failed internal validation checks")
	}

	// Validate Audience - check if audience is in the slice
	audienceFound := false
	for _, aud := range claims.Audience {
		if aud == av.cfg.Audience {
			audienceFound = true
			break
		}
	}
	if !audienceFound {
		return fmt.Errorf("invalid audience: expected %s, but token contains %v", av.cfg.Audience, claims.Audience)
	}

	// Validate Tenant ID (if configured)
	if av.cfg.TenantID != "" && claims.TenantID != av.cfg.TenantID {
		return fmt.Errorf("invalid tenant ID: expected %s, but got %s", av.cfg.TenantID, claims.TenantID)
	}

	// Dynamic Issuer validation - support both v1.0 and v2.0 formats
	expectedIssuerV1 := fmt.Sprintf("https://sts.windows.net/%s/", claims.TenantID)
	expectedIssuerV2 := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", claims.TenantID)
	if claims.Issuer != expectedIssuerV1 && claims.Issuer != expectedIssuerV2 {
		return fmt.Errorf("invalid issuer: got %s, expected %s or %s", claims.Issuer, expectedIssuerV1, expectedIssuerV2)
	}

	return nil
}

func (av *AzureADAuthVerifier) VerifyLogin(m *msg.Login) error {
	return av.verifyToken(m.PrivilegeKey)
}

func (av *AzureADAuthVerifier) VerifyPing(m *msg.Ping) error {
	if !slices.Contains(av.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	return av.verifyToken(m.PrivilegeKey)
}

func (av *AzureADAuthVerifier) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !slices.Contains(av.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	return av.verifyToken(m.PrivilegeKey)
}
