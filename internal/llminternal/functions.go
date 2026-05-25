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

package llminternal

import (
	"time"

	"google.golang.org/genai"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/internal/utils"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool/toolauth"
	"google.golang.org/adk/tool/toolconfirmation"
)

// generateRequestConfirmationEvent creates a new Event containing
// adk_request_confirmation function calls based on the requested confirmations.
// NOTE: The trigger for this in ADK Go is usually a tool.Context.RequestConfirmation call,
// not parsing a function_response_event like in the Python example.
// This function assumes you have a list of confirmations to process.
func generateRequestConfirmationEvent(
	invocationContext agent.InvocationContext,
	functionCallEvent *session.Event,
	functionResponseEvent *session.Event,
) *session.Event {
	if functionResponseEvent == nil || len(functionResponseEvent.Actions.RequestedToolConfirmations) == 0 {
		return nil
	}
	if functionCallEvent == nil || functionCallEvent.Content == nil {
		return nil
	}

	parts := []*genai.Part{}
	longRunningToolIDs := []string{}
	functionCallParts := make(map[string]*genai.Part, len(functionCallEvent.Content.Parts))
	for _, part := range functionCallEvent.Content.Parts {
		if part.FunctionCall != nil {
			functionCallParts[part.FunctionCall.ID] = part
		}
	}

	for funcID, confirmation := range functionResponseEvent.Actions.RequestedToolConfirmations {
		originalPart, ok := functionCallParts[funcID]
		if !ok || originalPart.FunctionCall == nil {
			continue
		}

		// Prepare arguments for the adk_request_confirmation call
		args := map[string]any{
			"originalFunctionCall": originalPart.FunctionCall,
			"toolConfirmation":     confirmation,
		}

		requestConfirmationFC := &genai.FunctionCall{
			ID:   utils.GenerateFunctionCallID(),
			Name: toolconfirmation.FunctionCallName,
			Args: args,
		}

		parts = append(parts, &genai.Part{
			FunctionCall:     requestConfirmationFC,
			ThoughtSignature: originalPart.ThoughtSignature,
		})
		longRunningToolIDs = append(longRunningToolIDs, requestConfirmationFC.ID)
	}

	if len(parts) == 0 {
		return nil
	}

	ev := session.NewEvent(invocationContext.InvocationID())
	ev.Author = invocationContext.Agent().Name()
	ev.Branch = invocationContext.Branch()
	ev.LLMResponse = model.LLMResponse{
		Content: &genai.Content{
			Parts: parts,
			Role:  genai.RoleModel,
		},
	}
	ev.LongRunningToolIDs = longRunningToolIDs
	return ev
}

// generateAuthEvent creates a new Event containing adk_request_credential function calls
// based on the RequestedAuthConfigs stored in the function response event's EventActions.
//
// This mirrors generateRequestConfirmationEvent: when a tool calls toolCtx.RequestCredential(cfg),
// the config is stored in EventActions.RequestedAuthConfigs[functionCallID]. This function
// iterates those entries and builds a genai.Content with FunctionCall parts that the client
// uses to open the OAuth popup.
//
// Each FunctionCall part is built via toolauth.BuildAuthRequestContentFromConfig which:
//   - Ensures the OAuth authorization URL is generated (via GenerateAuthRequest)
//   - Formats the auth config with camelCase keys for client compatibility
//   - Sets the FunctionCall name to "adk_request_credential" with the original tool's
//     functionCallID as the correlation ID
//
// The generated event includes LongRunningToolIDs to signal to the transport layer (REST/A2A)
// that this event requires user interaction before the flow can continue.
//
// Returns nil if the function response event has no RequestedAuthConfigs.
func generateAuthEvent(
	invocationContext agent.InvocationContext,
	functionResponseEvent *session.Event,
) *session.Event {
	// Only generate an auth event if the tool requested credentials.
	if functionResponseEvent == nil || len(functionResponseEvent.Actions.RequestedAuthConfigs) == 0 {
		return nil
	}

	var allParts []*genai.Part
	var allLongRunningIDs []string

	// Iterate over each auth config requested by tools during this invocation.
	// Each entry is keyed by the original tool's functionCallID.
	for functionCallID, authConfig := range functionResponseEvent.Actions.RequestedAuthConfigs {
		// BuildAuthRequestContentFromConfig generates the adk_request_credential FunctionCall
		// content with the OAuth URL and camelCase keys for client compatibility.
		content, longRunningIDs := toolauth.BuildAuthRequestContentFromConfig(functionCallID, authConfig)
		if content != nil && len(content.Parts) > 0 {
			allParts = append(allParts, content.Parts...)
			allLongRunningIDs = append(allLongRunningIDs, longRunningIDs...)
		}
	}

	if len(allParts) == 0 {
		return nil
	}

	// Build the event with the same invocation context as the tool response.
	// The Role is set to RoleModel because this is an event generated by the ADK runtime
	// (on behalf of the agent), not a user message.
	return &session.Event{
		InvocationID: invocationContext.InvocationID(),
		Author:       invocationContext.Agent().Name(),
		Branch:       invocationContext.Branch(),
		LLMResponse: model.LLMResponse{
			Content: &genai.Content{
				Parts: allParts,
				Role:  genai.RoleModel,
			},
		},
		Timestamp:          time.Now(),
		LongRunningToolIDs: allLongRunningIDs,
		Actions:            session.EventActions{},
	}
}
