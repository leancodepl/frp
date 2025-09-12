package auth

import (
	"context"
	"fmt"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
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
