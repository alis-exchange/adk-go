package toolauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// AuthConfigFromResponseMap parses a map (e.g. from a FunctionResponse.Response) into an
// AuthConfig struct. This is used by authPreprocessor to convert the client's OAuth callback
// payload into a typed config. Accepts both camelCase (adk-web, a2a-playground) and snake_case
// keys since different clients may use different conventions. The normalization step converts
// all keys to snake_case before JSON unmarshaling into the struct.
func AuthConfigFromResponseMap(m map[string]any) (AuthConfig, error) {
	if m == nil {
		return AuthConfig{}, fmt.Errorf("auth response map is nil")
	}
	// Normalize to snake_case for json.Unmarshal into our struct
	norm := normalizeAuthConfigKeys(m)
	data, err := json.Marshal(norm)
	if err != nil {
		return AuthConfig{}, fmt.Errorf("marshal normalized auth config: %w", err)
	}
	var cfg AuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AuthConfig{}, fmt.Errorf("unmarshal auth config: %w", err)
	}
	return cfg, nil
}

// normalizeAuthConfigKeys converts camelCase keys to snake_case recursively.
func normalizeAuthConfigKeys(m map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range m {
		normKey := camelToSnake(k)
		switch val := v.(type) {
		case map[string]any:
			out[normKey] = normalizeAuthConfigKeys(val)
		default:
			out[normKey] = v
		}
	}
	return out
}

// camelToSnake maps known camelCase auth config keys to snake_case. This is a
// lookup table for supported keys, not a generic converter.
func camelToSnake(s string) string {
	switch s {
	case "credentialKey":
		return "credential_key"
	case "rawAuthCredential":
		return "raw_auth_credential"
	case "exchangedAuthCredential":
		return "exchanged_auth_credential"
	case "oauth2":
		return "oauth2"
	case "apiKey":
		return "api_key"
	case "bearerToken":
		return "bearer_token"
	case "serviceAccount":
		return "service_account"
	case "jsonKey":
		return "json_key"
	case "clientId":
		return "client_id"
	case "clientSecret":
		return "client_secret"
	case "authUri":
		return "auth_uri"
	case "tokenUri":
		return "token_uri"
	case "redirectUri":
		return "redirect_uri"
	case "authResponseUri":
		return "auth_response_uri"
	case "accessToken":
		return "access_token"
	case "refreshToken":
		return "refresh_token"
	case "expiresAt":
		return "expires_at"
	case "inHeader":
		return "in_header"
	case "inQuery":
		return "in_query"
	default:
		return s
	}
}

// ExchangeAndStore completes the server-side OAuth token exchange and persists the result.
//
// This is the critical step between the user completing the OAuth popup and the tool being
// re-invoked with valid credentials. It is called by authPreprocessor (for REST/adk-web)
// and by the A2A event conversion layer.
//
// ## Credential Resolution
//
// The AuthConfig may carry credentials in two places:
//   - ExchangedAuthCredential: populated by the client with callback data (authResponseUri,
//     redirectUri). This is the "live" data from the current OAuth flow.
//   - RawAuthCredential: the static config originally provided by the tool (client_id,
//     client_secret, token_uri, scopes). These values don't change between flows.
//
// The function merges both: it takes callback-specific fields from ExchangedAuthCredential
// and falls back to RawAuthCredential for client_id, client_secret, and token_uri. This is
// necessary because some clients (e.g. a2a-playground) include rawAuthCredential with the
// static secrets, while exchangedAuthCredential only has the callback URL.
//
// ## Token Storage
//
// The resulting access/refresh tokens are stored via the StateWriter interface at key
// "temp:<credentialKey>". The state parameter accepts any type satisfying StateWriter
// (notably session.State, which implicitly satisfies it). Tools retrieve stored tokens
// via toolCtx.GetAuthResponse or by reading session state directly.
func ExchangeAndStore(ctx context.Context, cfg AuthConfig, state StateWriter) error {
	if state == nil {
		return fmt.Errorf("session state is nil")
	}
	if cfg.CredentialKey == "" {
		return fmt.Errorf("credential_key is required")
	}

	ex := cfg.ExchangedAuthCredential
	raw := cfg.RawAuthCredential
	if (ex == nil || ex.OAuth2 == nil) && (raw == nil || raw.OAuth2 == nil) {
		return fmt.Errorf("no oauth2 credential in auth config")
	}

	// Merge exchanged and raw credentials:
	// - o2 = primary source (exchanged), used for callback-specific fields (authResponseUri, redirectUri)
	// - rawO2 = fallback source (raw), used for static fields (client_id, client_secret, token_uri)
	// If either is nil, the other serves as both primary and fallback.
	var o2, rawO2 *OAuth2Credential
	if ex != nil {
		o2 = ex.OAuth2
	}
	if raw != nil {
		rawO2 = raw.OAuth2
	}
	if o2 == nil {
		o2 = rawO2
	}
	if rawO2 == nil {
		rawO2 = o2
	}
	if o2 == nil {
		return fmt.Errorf("no oauth2 credential in auth config")
	}

	// Extract auth_response_uri from the exchanged credential. This is the full URL
	// the OAuth provider redirected to (e.g. http://localhost:3000/oauth-callback?code=abc&state=xyz).
	authRespURI := ""
	if ex != nil && ex.OAuth2 != nil {
		authRespURI = ex.OAuth2.AuthResponseURI
	}
	if authRespURI == "" {
		return fmt.Errorf("auth_response_uri is required for exchange")
	}

	// Parse the authorization code from the callback URL's query parameters.
	parsed, err := url.Parse(authRespURI)
	if err != nil {
		return fmt.Errorf("invalid auth_response_uri: %w", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no code in auth_response_uri")
	}

	// The redirect_uri must match exactly what was used in the initial authorization request,
	// otherwise the token exchange will fail. Prefer the explicit redirectUri if provided;
	// fall back to deriving it from auth_response_uri by stripping query parameters.
	redirectURL := o2.RedirectURI
	if redirectURL == "" {
		redirectURL = parsed.Scheme + "://" + parsed.Host + parsed.Path
		if parsed.Path == "" && parsed.RawQuery != "" {
			redirectURL = parsed.Scheme + "://" + parsed.Host + "/"
		}
	}

	// Resolve token_uri with fallback chain: exchanged -> raw -> Google default.
	tokenURI := o2.TokenURI
	if tokenURI == "" {
		tokenURI = rawO2.TokenURI
	}
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	// Resolve client credentials with fallback from exchanged to raw. The raw credential
	// is the authoritative source for client_id and client_secret since these are configured
	// by the tool and don't change during the OAuth flow.
	clientID := o2.ClientID
	if clientID == "" {
		clientID = rawO2.ClientID
	}
	clientSecret := o2.ClientSecret
	if clientSecret == "" {
		clientSecret = rawO2.ClientSecret
	}
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("client_id and client_secret are required (from exchangedAuthCredential or rawAuthCredential)")
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o2.AuthURI,
			TokenURL: tokenURI,
		},
	}

	// Perform the actual OAuth2 authorization code exchange with the token endpoint.
	tok, err := config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("oauth2 exchange failed: %w", err)
	}

	// Persist the token in session state. Tools call GetCredential(credentialKey) which
	// reads from CredentialStatePrefix+credentialKey ("temp:<key>") to get these tokens.
	cred := AuthCredential{
		OAuth2: &OAuth2Credential{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			ExpiresAt:    tok.Expiry.Unix(),
		},
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	return state.Set(CredentialStatePrefix+cfg.CredentialKey, string(data))
}

// ExchangeAndStoreServiceAccount provides a non-interactive credential flow for tools that
// use Google service account authentication. Unlike ExchangeAndStore (which handles the
// OAuth authorization code flow and requires user interaction), this function takes the
// service account JSON key from RawAuthCredential.ServiceAccount, obtains an access token
// directly using Google's credentials API, and stores it in session state. This is useful
// for server-to-server authentication where no user consent is needed.
func ExchangeAndStoreServiceAccount(ctx context.Context, cfg AuthConfig, state StateWriter) error {
	if state == nil {
		return fmt.Errorf("session state is nil")
	}
	if cfg.CredentialKey == "" {
		return fmt.Errorf("credential_key is required")
	}
	raw := cfg.RawAuthCredential
	if raw == nil || raw.ServiceAccount == nil {
		return fmt.Errorf("raw_auth_credential with service_account is required")
	}
	sa := raw.ServiceAccount
	if len(sa.JSONKey) == 0 {
		return fmt.Errorf("service_account json_key is required")
	}

	creds, err := google.CredentialsFromJSON(ctx, sa.JSONKey, sa.Scopes...)
	if err != nil {
		return fmt.Errorf("service account credentials: %w", err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("service account token: %w", err)
	}

	cred := AuthCredential{
		OAuth2: &OAuth2Credential{
			AccessToken: tok.AccessToken,
			ExpiresAt:   tok.Expiry.Unix(),
		},
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	return state.Set(CredentialStatePrefix+cfg.CredentialKey, string(data))
}
