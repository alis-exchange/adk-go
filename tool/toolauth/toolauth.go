// Package toolauth provides structures and utilities for handling tool
// authentication within the ADK, mirroring the Python ADK's adk_request_credential
// protocol and supporting API_KEY, OAUTH2, HTTP Bearer, and SERVICE_ACCOUNT.
package toolauth

// FunctionCallName defines the specific name for the FunctionCall/FunctionResponse event
// emitted when a tool requires user OAuth authorization.
//
// Client applications must:
//  1. Listen for events containing adk_request_credential.
//  2. Extract auth_config.exchanged_auth_credential.oauth2.auth_uri and redirect the user.
//  3. On callback, send a FunctionResponse with name="adk_request_credential",
//     id=<original function call id>, response={auth_config with auth_response_uri set}.
const FunctionCallName = "adk_request_credential"

// AuthCredentialType matches Python ADK AuthCredentialTypes.
type AuthCredentialType string

const (
	AuthTypeOAuth2          AuthCredentialType = "OAUTH2"
	AuthTypeOpenIDConnect   AuthCredentialType = "OPEN_ID_CONNECT"
	AuthTypeAPIKey          AuthCredentialType = "API_KEY"
	AuthTypeHTTP            AuthCredentialType = "HTTP"
	AuthTypeServiceAccount  AuthCredentialType = "SERVICE_ACCOUNT"
)

// OAuth2Credential holds OAuth2 configuration and token data.
type OAuth2Credential struct {
	ClientID        string   `json:"client_id,omitempty"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	AuthURI         string   `json:"auth_uri,omitempty"`  // Generated for user redirect
	TokenURI        string   `json:"token_uri,omitempty"` // Token exchange endpoint
	RedirectURI     string   `json:"redirect_uri,omitempty"`
	AuthResponseURI string   `json:"auth_response_uri,omitempty"` // Callback URL from client
	State           string   `json:"state,omitempty"`
	Scopes          []string `json:"scopes,omitempty"` // OAuth scopes to request
	AccessToken     string   `json:"access_token,omitempty"`
	RefreshToken    string   `json:"refresh_token,omitempty"`
	ExpiresAt       int64    `json:"expires_at,omitempty"`
}

// APIKeyCredential holds an API key. No user interaction or exchange.
type APIKeyCredential struct {
	Key     string `json:"key,omitempty"`
	InQuery string `json:"in_query,omitempty"` // e.g. "api_key"
	InHeader string `json:"in_header,omitempty"` // e.g. "X-API-Key"
}

// BearerTokenCredential holds a Bearer token (e.g. from prior OAuth). No exchange.
type BearerTokenCredential struct {
	Token string `json:"token,omitempty"`
}

// ServiceAccountCredential holds service account config for token exchange.
type ServiceAccountCredential struct {
	JSONKey []byte   `json:"json_key,omitempty"` // Service account JSON key
	Scopes  []string `json:"scopes,omitempty"`
}

// AuthCredential wraps credential types (OAuth2, API key, Bearer, ServiceAccount).
type AuthCredential struct {
	OAuth2         *OAuth2Credential         `json:"oauth2,omitempty"`
	APIKey         *APIKeyCredential          `json:"api_key,omitempty"`
	BearerToken    *BearerTokenCredential     `json:"bearer_token,omitempty"`
	ServiceAccount *ServiceAccountCredential  `json:"service_account,omitempty"`
}

// AuthConfig holds the auth configuration for a credential request.
type AuthConfig struct {
	RawAuthCredential       *AuthCredential `json:"raw_auth_credential,omitempty"`
	ExchangedAuthCredential *AuthCredential `json:"exchanged_auth_credential,omitempty"`
	CredentialKey           string         `json:"credential_key,omitempty"`
	AuthType                AuthCredentialType `json:"auth_type,omitempty"`
}

// APIKeyScheme defines where to send an API key (header or query).
type APIKeyScheme struct {
	ParamName string `json:"param_name,omitempty"` // e.g. "X-API-Key" or "api_key"
	In        string `json:"in,omitempty"`        // "header" or "query"
}

// HTTPBearerScheme uses Authorization: Bearer <token>.
type HTTPBearerScheme struct {
	BearerFormat string `json:"bearer_format,omitempty"`
}

// OAuth2Scheme defines OAuth2 flow endpoints (authorization, token).
type OAuth2Scheme struct {
	AuthorizationURL string            `json:"authorization_url,omitempty"`
	TokenURL         string            `json:"token_url,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"` // scope -> description
}

// OpenIDConnectScheme extends OAuth2 with OIDC-specific config.
type OpenIDConnectScheme struct {
	AuthorizationEndpoint string            `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string            `json:"token_endpoint,omitempty"`
	Scopes                map[string]string `json:"scopes,omitempty"`
}

// AuthToolArguments are the arguments for the adk_request_credential FunctionCall.
type AuthToolArguments struct {
	FunctionCallID string     `json:"function_call_id"`
	AuthConfig     AuthConfig `json:"auth_config"`
}
