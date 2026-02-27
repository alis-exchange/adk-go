// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package toolauth

import (
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"

	"google.golang.org/genai"
)

// GenerateAuthRequest constructs the OAuth authorization URL that the client will open in a
// popup. It reads the client_id, redirect_uri, scopes, and endpoint URLs from the
// RawAuthCredential in the config, then uses oauth2.Config.AuthCodeURL to build the full
// authorization URL with state parameter and any AuthCodeOptions (e.g. AccessTypeOffline,
// ApprovalForce). The resulting URL is stored in ExchangedAuthCredential.OAuth2.AuthURI
// so the LLM flow layer (generateAuthEvent) or transport layer can include it in the
// adk_request_credential FunctionCall sent to the client.
//
// The returned AuthConfig is the input config augmented with ExchangedAuthCredential.
// Called by toolContext.RequestCredential and BuildAuthRequestContentFromConfig.
func GenerateAuthRequest(cfg AuthConfig) (AuthConfig, error) {
	raw := cfg.RawAuthCredential
	if raw == nil || raw.OAuth2 == nil {
		return cfg, fmt.Errorf("raw_auth_credential with oauth2 is required")
	}
	o2 := raw.OAuth2
	if o2.ClientID == "" || o2.RedirectURI == "" {
		return cfg, fmt.Errorf("client_id and redirect_uri are required")
	}

	state := o2.State
	if state == "" {
		state = "adk-auth-state"
	}

	tokenURI := o2.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	authURLField := o2.AuthURI
	if authURLField == "" {
		authURLField = "https://accounts.google.com/o/oauth2/auth"
	}

	config := oauth2.Config{
		ClientID:     o2.ClientID,
		ClientSecret: o2.ClientSecret,
		RedirectURL:  o2.RedirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURLField,
			TokenURL: tokenURI,
		},
		Scopes: o2.Scopes,
	}

	authURL := config.AuthCodeURL(state, cfg.AuthCodeOptions...)
	out := cfg
	if out.ExchangedAuthCredential == nil {
		out.ExchangedAuthCredential = &AuthCredential{
			OAuth2: &OAuth2Credential{},
		}
	}
	if out.ExchangedAuthCredential.OAuth2 == nil {
		out.ExchangedAuthCredential.OAuth2 = &OAuth2Credential{}
	}
	out.ExchangedAuthCredential.OAuth2.AuthURI = authURL
	out.ExchangedAuthCredential.OAuth2.State = state
	out.ExchangedAuthCredential.OAuth2.RedirectURI = o2.RedirectURI
	return out, nil
}

// IsAuthRequiredInStateDelta checks whether a StateDelta map contains a pending auth request.
// This is the backward-compatible check for the legacy flow where tools stored auth configs
// in StateDelta under "adk_auth_request_<functionCallID>" keys. In the new flow, consumers
// should check EventActions.RequestedAuthConfigs first and fall back to this for compatibility.
//
// Parameters:
//   - stateDelta: the map from EventActions.StateDelta (may be nil).
//
// Returns true if any key in stateDelta starts with StateDeltaKeyPrefix ("adk_auth_request_").
func IsAuthRequiredInStateDelta(stateDelta map[string]any) bool {
	if stateDelta == nil {
		return false
	}
	for k := range stateDelta {
		if len(k) >= len(StateDeltaKeyPrefix) && k[:len(StateDeltaKeyPrefix)] == StateDeltaKeyPrefix {
			return true
		}
	}
	return false
}

// ExtractAuthRequestFromState extracts a pending auth request from a key-value map. The map
// can be an event's StateDelta or the full session state (since StateDelta gets merged into
// state after commit). This is used by the A2A and REST layers for backward-compatible
// detection of legacy StateDelta-based auth requests, and also by authPreprocessor for
// reading stored auth configs from session state.
//
// The key format is "adk_auth_request_<functionCallID>" and the value is the AuthConfig
// (as a map, pointer, or value). The functionCallID links back to the original tool
// FunctionCall that requested credentials, enabling the preprocessor to re-invoke that
// tool after token exchange.
//
// Returns ok=false if no auth request key is found.
func ExtractAuthRequestFromState(state map[string]any) (functionCallID string, authConfig AuthConfig, ok bool) {
	if state == nil {
		return "", AuthConfig{}, false
	}
	for k, v := range state {
		if len(k) <= len(StateDeltaKeyPrefix) || k[:len(StateDeltaKeyPrefix)] != StateDeltaKeyPrefix {
			continue
		}
		functionCallID = k[len(StateDeltaKeyPrefix):]
		if functionCallID == "" {
			continue
		}
		var cfg AuthConfig
		switch val := v.(type) {
		case map[string]any:
			data, err := json.Marshal(val)
			if err != nil {
				continue
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				continue
			}
		case *AuthConfig:
			if val != nil {
				cfg = *val
			}
		case AuthConfig:
			cfg = val
		default:
			continue
		}
		return functionCallID, cfg, true
	}
	return "", AuthConfig{}, false
}

// BuildAuthRequestContentFromConfig builds the genai.Content that represents an
// adk_request_credential FunctionCall for the client. This is used by the A2A
// authRequiredProcessor to emit auth-required events with the OAuth URL.
//
// The content contains a single FunctionCall part with:
//   - Name: "adk_request_credential"
//   - ID: the original tool's functionCallID (for correlation on callback)
//   - Args: {functionCallId, authConfig} with camelCase keys for client compatibility
//
// If the auth config already has a fully populated ExchangedAuthCredential with an authUri,
// it is used as-is. Otherwise, GenerateAuthRequest is called to build the OAuth URL from
// the raw credential. Returns the content and a list of long-running tool IDs (the
// functionCallID) which signals to the client that this call requires user interaction.
func BuildAuthRequestContentFromConfig(functionCallID string, authConfig AuthConfig) (*genai.Content, []string) {
	cfg := authConfig
	if cfg.ExchangedAuthCredential == nil || cfg.ExchangedAuthCredential.OAuth2 == nil ||
		cfg.ExchangedAuthCredential.OAuth2.AuthURI == "" {
		if generated, err := GenerateAuthRequest(cfg); err == nil {
			cfg = generated
		}
	}
	argsMap := map[string]any{
		"functionCallId": functionCallID,
		"authConfig":     toFrontendAuthConfigMap(cfg),
	}
	content := &genai.Content{
		Parts: []*genai.Part{
			{
				FunctionCall: &genai.FunctionCall{
					Name: FunctionCallName,
					ID:   functionCallID,
					Args: argsMap,
				},
			},
		},
		Role: genai.RoleUser,
	}
	return content, []string{functionCallID}
}

// BuildAuthCallbackContent constructs the user message that represents the OAuth callback.
// This is used by the A2A event conversion layer when converting an incoming A2A message
// (containing the auth callback URL) into a genai.Content for the runner.
//
// The content is a FunctionResponse with name="adk_request_credential" that carries the full
// auth config including the auth_response_uri (callback URL with ?code=...). When the runner
// processes this message, authPreprocessor will detect the FunctionResponse, call
// ExchangeAndStore to exchange the code for tokens, and re-invoke the original tool.
//
// The response payload is serialized as a snake_case map for compatibility with
// AuthConfigFromResponseMap which normalizes both camelCase and snake_case keys.
func BuildAuthCallbackContent(functionCallID string, authConfig AuthConfig, callbackURL string) *genai.Content {
	cfg := authConfig
	if cfg.ExchangedAuthCredential == nil {
		cfg.ExchangedAuthCredential = &AuthCredential{OAuth2: &OAuth2Credential{}}
	}
	if cfg.ExchangedAuthCredential.OAuth2 == nil {
		cfg.ExchangedAuthCredential.OAuth2 = &OAuth2Credential{}
	}
	cfg.ExchangedAuthCredential.OAuth2.AuthResponseURI = callbackURL

	// Marshal to map for AuthConfigFromResponseMap compatibility (snake_case)
	data, _ := json.Marshal(cfg)
	var responseMap map[string]any
	if err := json.Unmarshal(data, &responseMap); err != nil {
		responseMap = map[string]any{"credential_key": cfg.CredentialKey, "auth_response_uri": callbackURL}
	}

	return &genai.Content{
		Role: genai.RoleUser,
		Parts: []*genai.Part{
			{
				FunctionResponse: &genai.FunctionResponse{
					ID:       functionCallID,
					Name:     FunctionCallName,
					Response: responseMap,
				},
			},
		},
	}
}

// toFrontendAuthConfigMap converts AuthConfig to a map with camelCase keys for
// adk-web and other clients that expect JavaScript-style property names.
func toFrontendAuthConfigMap(cfg AuthConfig) map[string]any {
	out := make(map[string]any)
	if cfg.CredentialKey != "" {
		out["credentialKey"] = cfg.CredentialKey
	}
	if cfg.RawAuthCredential != nil && cfg.RawAuthCredential.OAuth2 != nil {
		out["rawAuthCredential"] = map[string]any{
			"oauth2": oauth2CredToFrontendMap(cfg.RawAuthCredential.OAuth2),
		}
	}
	if cfg.ExchangedAuthCredential != nil && cfg.ExchangedAuthCredential.OAuth2 != nil {
		out["exchangedAuthCredential"] = map[string]any{
			"oauth2": oauth2CredToFrontendMap(cfg.ExchangedAuthCredential.OAuth2),
		}
	}
	return out
}

// oauth2CredToFrontendMap converts OAuth2Credential fields to camelCase map keys.
func oauth2CredToFrontendMap(o *OAuth2Credential) map[string]any {
	if o == nil {
		return nil
	}
	m := make(map[string]any)
	if o.ClientID != "" {
		m["clientId"] = o.ClientID
	}
	if o.ClientSecret != "" {
		m["clientSecret"] = o.ClientSecret
	}
	if o.AuthURI != "" {
		m["authUri"] = o.AuthURI
	}
	if o.TokenURI != "" {
		m["tokenUri"] = o.TokenURI
	}
	if o.RedirectURI != "" {
		m["redirectUri"] = o.RedirectURI
	}
	if o.AuthResponseURI != "" {
		m["authResponseUri"] = o.AuthResponseURI
	}
	if o.State != "" {
		m["state"] = o.State
	}
	if len(o.Scopes) > 0 {
		m["scopes"] = o.Scopes
	}
	if o.AccessToken != "" {
		m["accessToken"] = o.AccessToken
	}
	if o.RefreshToken != "" {
		m["refreshToken"] = o.RefreshToken
	}
	if o.ExpiresAt != 0 {
		m["expiresAt"] = o.ExpiresAt
	}
	return m
}
