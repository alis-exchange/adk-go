package toolauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"google.golang.org/adk/session"
)

// AuthConfigFromResponseMap parses a map (e.g. from FunctionResponse) into AuthConfig.
// Accepts both camelCase (adk-web) and snake_case keys for compatibility.
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

func camelToSnake(s string) string {
	// Map known camelCase keys to snake_case for auth config
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

// ExchangeAndStore parses the auth_response_uri for the authorization code,
// exchanges it for a token, and stores the resulting credential in session state.
func ExchangeAndStore(ctx context.Context, cfg AuthConfig, state session.State) error {
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

	// Prefer exchanged for callback data (authResponseUri, redirect, state); fall back to raw for client_id/secret/token_uri.
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

	authRespURI := ""
	if ex != nil && ex.OAuth2 != nil {
		authRespURI = ex.OAuth2.AuthResponseURI
	}
	if authRespURI == "" {
		return fmt.Errorf("auth_response_uri is required for exchange")
	}

	parsed, err := url.Parse(authRespURI)
	if err != nil {
		return fmt.Errorf("invalid auth_response_uri: %w", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no code in auth_response_uri")
	}

	redirectURL := o2.RedirectURI
	if redirectURL == "" {
		// Use the auth_response_uri without query params as redirect (common pattern)
		redirectURL = parsed.Scheme + "://" + parsed.Host + parsed.Path
		if parsed.Path == "" && parsed.RawQuery != "" {
			redirectURL = parsed.Scheme + "://" + parsed.Host + "/"
		}
	}

	tokenURI := o2.TokenURI
	if tokenURI == "" {
		tokenURI = rawO2.TokenURI
	}
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

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

	tok, err := config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("oauth2 exchange failed: %w", err)
	}

	// Store the token as AuthCredential for tools to read
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
	// Store as JSON string for consistent retrieval
	return state.Set(CredentialStatePrefix+cfg.CredentialKey, string(data))
}

// ExchangeAndStoreServiceAccount uses a service account JSON key to obtain an
// access token and stores it in session state. No user interaction required.
func ExchangeAndStoreServiceAccount(ctx context.Context, cfg AuthConfig, state session.State) error {
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
