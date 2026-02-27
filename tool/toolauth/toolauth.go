// Package toolauth provides the adk_request_credential protocol implementation for ADK tools
// that require user authentication (primarily OAuth2).
//
// This is a leaf package: it does NOT import the session package, which allows session to
// import toolauth for the EventActions.RequestedAuthConfigs field without creating an import
// cycle. This follows the same pattern as tool/toolconfirmation.
//
// # End-to-End Auth Flow
//
// The protocol involves coordination between three layers: the tool, the ADK runtime, and
// the client (adk-web, a2a-playground, or any compliant frontend).
//
//  1. Tool requests credential: A tool calls toolCtx.RequestCredential(cfg) or
//     toolCtx.GetAuthResponse(cfg). If no stored credential exists, the config is stored
//     in EventActions.RequestedAuthConfigs[functionCallID] and the tool returns a
//     "Pending User Authorization" message.
//
//  2. Runtime generates auth event: The LLM flow layer (generateAuthEvent in llminternal)
//     detects RequestedAuthConfigs on the event and yields an adk_request_credential
//     FunctionCall event with the OAuth URL and LongRunningToolIDs.
//
//  3. Client handles OAuth: The client opens an OAuth popup, the user authenticates, and the
//     OAuth provider redirects back with an authorization code. The client sends the callback
//     URL back as a FunctionResponse (name="adk_request_credential") or as an authCallbackUrl.
//
//  4. Runtime exchanges code: authPreprocessor (for REST) or the A2A event converter (for A2A)
//     picks up the callback, calls ExchangeAndStore to exchange the code for access/refresh
//     tokens, and stores the tokens in session state at "temp:<credentialKey>".
//
//  5. Tool re-invocation: authPreprocessor finds the original tool call and re-invokes it.
//     This time, GetAuthResponse finds the stored token and the tool completes successfully.
//
// For backward compatibility, the StateDelta-based flow (storing auth config under
// "adk_auth_request_<functionCallID>") is still supported as a fallback. New tools should
// use the RequestCredential/GetAuthResponse API on tool.Context.
package toolauth

import "golang.org/x/oauth2"

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

// AuthConfig holds the full authentication configuration passed between the tool, runtime,
// and client during the adk_request_credential flow. It carries two credential slots:
//
//   - RawAuthCredential: the static configuration from the tool definition (client_id,
//     client_secret, scopes, endpoint URLs). This does not change between invocations.
//   - ExchangedAuthCredential: populated during the flow with dynamic data. On the outbound
//     leg (tool -> client), it contains the generated auth_uri for the OAuth popup. On the
//     inbound leg (client -> runtime), it contains the auth_response_uri (callback URL with code).
//
// CredentialKey is the identifier used to store/retrieve tokens in session state.
type AuthConfig struct {
	RawAuthCredential       *AuthCredential       `json:"raw_auth_credential,omitempty"`
	ExchangedAuthCredential *AuthCredential       `json:"exchanged_auth_credential,omitempty"`
	CredentialKey           string                `json:"credential_key,omitempty"`
	AuthType                AuthCredentialType    `json:"auth_type,omitempty"`

	// AuthCodeOptions holds additional oauth2.AuthCodeOption values passed to
	// oauth2.Config.AuthCodeURL when generating the authorization URL. Common
	// options include oauth2.AccessTypeOffline (to get a refresh token) and
	// oauth2.ApprovalForce (to always show the consent screen). The json:"-"
	// tag excludes this field from serialization since AuthCodeOption is a
	// function type that cannot be marshaled.
	AuthCodeOptions []oauth2.AuthCodeOption `json:"-"`
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

// StateWriter is a minimal interface for persisting key-value data in session state.
// It is used by ExchangeAndStore and ExchangeAndStoreServiceAccount to store OAuth tokens
// after a successful token exchange without importing the session package directly.
//
// The session.State interface implicitly satisfies StateWriter (it has a Set method with
// the same signature), so callers can pass session.State values directly. This decoupling
// is what makes toolauth a leaf package: it defines its own narrow interface instead of
// depending on the full session package, which would create an import cycle since session
// imports toolauth for EventActions.RequestedAuthConfigs.
type StateWriter interface {
	Set(key string, value any) error
}

// AuthToolArguments are the arguments for the adk_request_credential FunctionCall.
type AuthToolArguments struct {
	FunctionCallID string     `json:"function_call_id"`
	AuthConfig     AuthConfig `json:"auth_config"`
}
