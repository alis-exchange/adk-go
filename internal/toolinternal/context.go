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

package toolinternal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/genai"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/artifact"
	contextinternal "google.golang.org/adk/internal/context"
	"google.golang.org/adk/memory"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/toolauth"
	"google.golang.org/adk/tool/toolconfirmation"
)

type internalArtifacts struct {
	agent.Artifacts
	eventActions *session.EventActions
}

func (ia *internalArtifacts) Save(ctx context.Context, name string, data *genai.Part) (*artifact.SaveResponse, error) {
	resp, err := ia.Artifacts.Save(ctx, name, data)
	if err != nil {
		return resp, err
	}
	if ia.eventActions != nil {
		if ia.eventActions.ArtifactDelta == nil {
			ia.eventActions.ArtifactDelta = make(map[string]int64)
		}
		// TODO: RWLock, check the version stored is newer in case multiple tools save the same file.
		ia.eventActions.ArtifactDelta[name] = resp.Version
	}
	return resp, nil
}

func NewToolContext(ctx agent.InvocationContext, functionCallID string, actions *session.EventActions, confirmation *toolconfirmation.ToolConfirmation) tool.Context {
	if functionCallID == "" {
		functionCallID = uuid.NewString()
	}
	if actions == nil {
		actions = &session.EventActions{StateDelta: make(map[string]any)}
	}
	if actions.StateDelta == nil {
		actions.StateDelta = make(map[string]any)
	}
	if actions.ArtifactDelta == nil {
		actions.ArtifactDelta = make(map[string]int64)
	}
	cbCtx := contextinternal.NewCallbackContextWithDelta(ctx, actions.StateDelta, actions.ArtifactDelta)

	return &toolContext{
		CallbackContext:   cbCtx,
		invocationContext: ctx,
		functionCallID:    functionCallID,
		eventActions:      actions,
		artifacts: &internalArtifacts{
			Artifacts:    ctx.Artifacts(),
			eventActions: actions,
		},
		toolConfirmation: confirmation,
	}
}

type toolContext struct {
	agent.CallbackContext
	invocationContext agent.InvocationContext
	functionCallID    string
	eventActions      *session.EventActions
	artifacts         *internalArtifacts
	toolConfirmation  *toolconfirmation.ToolConfirmation
}

func (c *toolContext) Artifacts() agent.Artifacts {
	return c.artifacts
}

func (c *toolContext) FunctionCallID() string {
	return c.functionCallID
}

func (c *toolContext) Actions() *session.EventActions {
	return c.eventActions
}

func (c *toolContext) AgentName() string {
	return c.invocationContext.Agent().Name()
}

func (c *toolContext) SearchMemory(ctx context.Context, query string) (*memory.SearchResponse, error) {
	if c.invocationContext.Memory() == nil {
		return nil, fmt.Errorf("memory service is not set")
	}
	return c.invocationContext.Memory().Search(ctx, query)
}

func (c *toolContext) ToolConfirmation() *toolconfirmation.ToolConfirmation {
	return c.toolConfirmation
}

// SessionState returns the session's state for reading. Used by CredentialHelper
// and other tool auth flows to retrieve stored OAuth credentials (e.g. after
// ExchangeAndStore in the adk_request_credential callback).
func (c *toolContext) SessionState() session.ReadonlyState {
	if c.invocationContext.Session() == nil {
		return nil
	}
	return c.invocationContext.Session().State()
}

func (c *toolContext) RequestConfirmation(hint string, payload any) error {
	if c.functionCallID == "" {
		return fmt.Errorf("error function call id not set when requesting confirmation for tool")
	}
	if c.eventActions.RequestedToolConfirmations == nil {
		c.eventActions.RequestedToolConfirmations = make(map[string]toolconfirmation.ToolConfirmation)
	}
	c.eventActions.RequestedToolConfirmations[c.functionCallID] = toolconfirmation.ToolConfirmation{
		Hint:      hint,
		Confirmed: false,
		Payload:   payload,
	}
	// SkipSummarization stops the agent loop after this tool call. Without it,
	// the function response event becomes lastEvent and IsFinalResponse() returns
	// false (hasFunctionResponses == true), causing the loop to continue.
	// This matches the behavior of the built-in RequireConfirmation path in
	// functiontool (function.go).
	c.eventActions.SkipSummarization = true
	return nil
}

// RequestCredential stores an OAuth auth config in EventActions.RequestedAuthConfigs so the
// LLM flow layer (generateAuthEvent) will yield an adk_request_credential event to the
// client. This is the auth equivalent of RequestConfirmation: it signals that the tool
// needs user authorization before it can proceed.
//
// The config is first passed through GenerateAuthRequest to build the OAuth authorization
// URL (populating ExchangedAuthCredential.OAuth2.AuthURI). The resulting config is stored
// keyed by the tool's functionCallID so the preprocessor can correlate the callback.
//
// SkipSummarization is set to true to stop the agent loop after this tool call, matching
// the behavior of RequestConfirmation. Without it, the function response would trigger
// another LLM round.
func (c *toolContext) RequestCredential(cfg toolauth.AuthConfig) error {
	if c.functionCallID == "" {
		return fmt.Errorf("RequestCredential requires function_call_id")
	}
	if c.eventActions.RequestedAuthConfigs == nil {
		c.eventActions.RequestedAuthConfigs = make(map[string]toolauth.AuthConfig)
	}

	// Generate the OAuth authorization URL from the raw credential config.
	// This populates ExchangedAuthCredential.OAuth2.AuthURI which the client
	// uses to open the OAuth popup.
	generated, err := toolauth.GenerateAuthRequest(cfg)
	if err != nil {
		return fmt.Errorf("generate auth request: %w", err)
	}

	c.eventActions.RequestedAuthConfigs[c.functionCallID] = generated

	// Stop the agent loop after this tool call so the auth event can be sent
	// to the client. Same rationale as RequestConfirmation.
	c.eventActions.SkipSummarization = true
	return nil
}

// GetAuthResponse checks session state for a previously exchanged credential and returns it.
// If tokens are available (i.e. the user has completed the OAuth flow and authPreprocessor
// has called ExchangeAndStore), it returns the AuthCredential containing the access token.
// If no credential is found, it returns (nil, nil) without any side effects.
//
// The credential lookup key is CredentialStatePrefix + cfg.CredentialKey
// (e.g. "temp:google_user_info"). After ExchangeAndStore completes the token exchange,
// it stores the AuthCredential JSON at this key in session state.
//
// This is a pure read operation -- it does NOT call RequestCredential. The decision to
// initiate the auth flow is left to the tool developer. This matches the adk-python pattern
// where get_auth_response and request_credential are independent methods.
//
// Typical usage:
//
//	cred, err := toolCtx.GetAuthResponse(myConfig)
//	if err != nil { return nil, err }
//	if cred == nil {
//	    if err := toolCtx.RequestCredential(myConfig); err != nil { return nil, err }
//	    return "Pending authorization", nil
//	}
//	// Use cred.OAuth2.AccessToken
func (c *toolContext) GetAuthResponse(cfg toolauth.AuthConfig) (*toolauth.AuthCredential, error) {
	state := c.SessionState()
	if state == nil || cfg.CredentialKey == "" {
		return nil, nil
	}

	// Attempt to read the stored credential from session state.
	val, err := state.Get(toolauth.CredentialStatePrefix + cfg.CredentialKey)
	if err == nil && val != nil {
		if s, ok := val.(string); ok {
			var cred toolauth.AuthCredential
			if json.Unmarshal([]byte(s), &cred) == nil {
				return &cred, nil
			}
		}
	}

	return nil, nil
}
