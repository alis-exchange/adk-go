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

// GenerateAuthRequest builds the auth URL and populates ExchangedAuthCredential
// with AuthURI and State. Returns the updated AuthConfig for the tool to put in StateDelta.
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

// IsAuthRequired returns true if the event indicates an auth request (tool returned
// "Pending User Authorization" and set StateDelta with auth config).
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

// ExtractAuthRequest finds the auth request in StateDelta and returns the
// functionCallID and AuthConfig. ok is false if none found.
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

// ExtractAuthRequestFromState finds a pending auth request in session state
// (same structure as StateDelta) and returns functionCallID and AuthConfig.
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

// BuildAuthRequestContentFromConfig builds genai.Content and LongRunningToolIDs
// for the adk_request_credential flow from an existing auth config (e.g. from
// StateDelta). Uses authConfig as-is when ExchangedAuthCredential is present.
// Fallback to GenerateAuthRequest only when ExchangedAuthCredential is empty.
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

// BuildAuthCallbackContent builds genai.Content for the OAuth callback: a user
// message with a FunctionResponse for adk_request_credential containing the
// callback URL. authPreprocessor will find this and run ExchangeAndStore.
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

// BuildAuthRequestEvent builds a session.Event for the adk_request_credential
// flow. Uses camelCase keys (authConfig, exchangedAuthCredential, authUri, etc.)
// to match adk-web expectations. Returns nil if auth config cannot be built.
// The invocationID is taken from the source event for proper correlation.
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
