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

	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// GenerateAuthRequest constructs the OAuth authorization URL that the client will open in a
// popup. It reads the client_id, redirect_uri, scopes, and endpoint URLs from the
// RawAuthCredential in the config, then uses oauth2.Config.AuthCodeURL to build the full
// authorization URL with state parameter. The resulting URL is stored in
// ExchangedAuthCredential.OAuth2.AuthURI so the REST/A2A layer can include it in the
// adk_request_credential FunctionCall sent to the client.
//
// The returned AuthConfig is the input config augmented with ExchangedAuthCredential; the
// caller (typically a CredentialHelper) stores this in StateDelta for downstream processing.
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

	authURL := config.AuthCodeURL(state)
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

// IsAuthRequired returns true if the event contains a pending auth request in its StateDelta.
// When a tool calls RequestCredential and no stored credential is found, the CredentialHelper
// stores the auth config in StateDelta under a key prefixed with "adk_auth_request_". This
// function checks for the presence of such keys, indicating the event should be transformed
// into an adk_request_credential FunctionCall for the client.
func IsAuthRequired(event *session.Event) bool {
	if event == nil || event.Actions.StateDelta == nil {
		return false
	}
	for k := range event.Actions.StateDelta {
		if len(k) >= len(StateDeltaKeyPrefix) && k[:len(StateDeltaKeyPrefix)] == StateDeltaKeyPrefix {
			return true
		}
	}
	return false
}

// ExtractAuthRequest extracts the pending auth request from an event's StateDelta. The key
// format is "adk_auth_request_<functionCallID>" and the value is the AuthConfig (as a map,
// pointer, or value). The functionCallID links back to the original tool FunctionCall that
// requested credentials, enabling the preprocessor to re-invoke that tool after token exchange.
// Returns ok=false if no auth request key is found in StateDelta.
func ExtractAuthRequest(event *session.Event) (functionCallID string, authConfig AuthConfig, ok bool) {
	if event == nil || event.Actions.StateDelta == nil {
		return "", AuthConfig{}, false
	}
	for k, v := range event.Actions.StateDelta {
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

// ExtractAuthRequestFromState is like ExtractAuthRequest but reads from a session state map
// instead of an event's StateDelta. This is used by the A2A layer when processing incoming
// messages: after events are committed, the auth config is available in session state (since
// StateDelta gets merged into state). Returns ok=false if no auth request key is found.
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

// BuildAuthRequestEvent builds a session.Event representing the adk_request_credential
// FunctionCall for the REST (adk-web) flow. Unlike BuildAuthRequestContentFromConfig (used
// by A2A), this produces a full session.Event that replaces the original tool-response event
// in the SSE/REST response stream.
//
// The event preserves the source event's ID, branch, timestamp, and invocationID so the
// client can correlate the auth request with the original invocation. The LLMResponse.Content
// contains the adk_request_credential FunctionCall with camelCase keys matching adk-web's
// expected format. LongRunningToolIDs signals that this event requires user interaction
// (the OAuth popup) before the flow can continue.
//
// Returns nil if GenerateAuthRequest fails (e.g. missing required fields in raw credential).
func BuildAuthRequestEvent(sourceEvent *session.Event, functionCallID string, authConfig AuthConfig) *session.Event {
	cfg, err := GenerateAuthRequest(authConfig)
	if err != nil {
		return nil
	}
	argsMap := map[string]any{
		"functionCallId": functionCallID,
		"authConfig":     toFrontendAuthConfigMap(cfg),
	}
	invocationID := ""
	if sourceEvent != nil {
		invocationID = sourceEvent.InvocationID
	}
	ev := session.NewEvent(invocationID)
	ev.Author = "agent"
	if sourceEvent != nil {
		ev.ID = sourceEvent.ID
		ev.Branch = sourceEvent.Branch
		ev.Timestamp = sourceEvent.Timestamp
	}
	ev.LLMResponse.Content = &genai.Content{
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
	ev.LongRunningToolIDs = []string{functionCallID}
	return ev
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
