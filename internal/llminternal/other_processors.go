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
	"encoding/json"
	"fmt"
	"iter"

	"google.golang.org/genai"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/internal/utils"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/toolauth"
)

func nlPlanningRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	// TODO: implement (adk-python src/google/adk/flows/llm_flows/_nl_plnning.py)
	return func(yield func(*session.Event, error) bool) {}
}

func codeExecutionRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	// TODO: implement (adk-python src/google/adk/flows/llm_flows/_code_execution.py)
	return func(yield func(*session.Event, error) bool) {}
}

// authPreprocessor handles the server-side OAuth callback in the adk_request_credential protocol.
//
// ## Protocol Overview
//
// When a tool needs user authorization (e.g. OAuth), it calls CredentialHelper.RequestCredential
// which stores auth config in StateDelta under the key "adk_auth_request_<functionCallID>".
// The REST layer (or A2A processor) transforms this into an adk_request_credential FunctionCall
// event that clients recognize. The client opens an OAuth popup, the user signs in, and the
// client sends back a FunctionResponse with name="adk_request_credential" containing the
// auth config with authResponseUri (the callback URL with ?code=...).
//
// ## What This Preprocessor Does
//
// On the next invocation (after the client sends the OAuth callback), this preprocessor runs
// before the LLM is called and:
//
//  1. Scans session events (newest first) for a user-authored FunctionResponse named
//     "adk_request_credential". This is the OAuth callback from the client.
//
//  2. Parses the auth config from the response. Clients may send the config in different
//     formats: (a) directly as the FunctionResponse.Response map, (b) wrapped in a "response"
//     key as a JSON string, or (c) wrapped in a "response" key as a nested map. All three
//     formats are supported.
//
//  3. Calls ExchangeAndStore which extracts the authorization code from auth_response_uri,
//     exchanges it with the OAuth provider for access/refresh tokens, and stores the
//     resulting credential in session state at "temp:<credentialKey>".
//
//  4. Finds the original tool FunctionCall (e.g. get_user_info) that triggered the auth
//     request by matching the functionCallID. The adk_request_credential FunctionResponse
//     uses the same ID as the original tool call.
//
//  5. Re-invokes that original tool via handleFunctionCalls. This time, the tool's
//     GetCredential call will find the stored token and complete successfully.
//
// If no adk_request_credential FunctionResponse is found (normal invocations without OAuth
// callback), the preprocessor returns immediately without yielding any events.
func authPreprocessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	return func(yield func(*session.Event, error) bool) {
		// Build a lookup map of available tools so we can re-invoke the original
		// tool after storing credentials.
		toolsmap := make(map[string]tool.Tool)
		for _, t := range f.Tools {
			toolsmap[t.Name()] = t
		}

		// Collect all session events. We need the full history to find both the
		// OAuth callback (FunctionResponse) and the original tool call (FunctionCall).
		var events []*session.Event
		if ctx.Session() != nil {
			for e := range ctx.Session().Events().All() {
				events = append(events, e)
			}
		}

		type authResp struct {
			cfg    toolauth.AuthConfig
			callID string
		}
		var authResponses []authResp

		// Walk events from most recent to oldest. The OAuth callback FunctionResponse
		// will be in a recent user-authored event. We only look at user events because
		// the client sends the callback as a user message.
		for k := len(events) - 1; k >= 0; k-- {
			event := events[k]
			if event.Author != "user" {
				continue
			}
			responses := utils.FunctionResponses(event.Content)
			if len(responses) == 0 {
				continue
			}
			for _, funcResp := range responses {
				// Only process adk_request_credential responses (OAuth callbacks).
				if funcResp.Name != toolauth.FunctionCallName {
					continue
				}

				// Parse the auth config from the FunctionResponse payload.
				var cfg toolauth.AuthConfig
				if funcResp.Response != nil {
					var respMap map[string]any

					// Handle multiple response formats from different clients:
					// - adk-web wraps the auth config in a "response" key (as JSON string or map)
					// - a2a-playground sends the auth config directly in the response map
					resp, hasResponseKey := funcResp.Response["response"]
					if hasResponseKey && len(funcResp.Response) == 1 {
						// Wrapped format: {"response": <string or map>}
						if jsonString, ok := resp.(string); ok {
							if err := json.Unmarshal([]byte(jsonString), &respMap); err != nil {
								yield(nil, fmt.Errorf("auth preprocessor: failed to unmarshal auth response for event %q: %w", event.ID, err))
								return
							}
						} else if m, ok := resp.(map[string]any); ok {
							respMap = m
						} else {
							yield(nil, fmt.Errorf("auth preprocessor: response key value is not string or object for event %q", event.ID))
							return
						}
					} else {
						// Direct format: the response map IS the auth config
						respMap = funcResp.Response
					}

					// Normalize camelCase/snake_case keys and parse into AuthConfig struct.
					var err error
					cfg, err = toolauth.AuthConfigFromResponseMap(respMap)
					if err != nil {
						yield(nil, fmt.Errorf("auth preprocessor: %w", err))
						return
					}
				}

				// Exchange the authorization code for tokens and store in session state.
				// After this, tools calling GetCredential will find the stored token.
				if ctx.Session() != nil {
					if err := toolauth.ExchangeAndStore(ctx, cfg, ctx.Session().State()); err != nil {
						yield(nil, fmt.Errorf("auth preprocessor: exchange and store failed: %w", err))
						return
					}
				}
				authResponses = append(authResponses, authResp{cfg: cfg, callID: funcResp.ID})
				// Only process the first (most recent) auth callback per invocation.
				break
			}
		}

		// No OAuth callback found; this is a normal invocation. Return without
		// yielding events so the flow proceeds to the LLM call.
		if len(authResponses) == 0 {
			return
		}

		// For each processed auth callback, find the original tool call that
		// requested credentials and re-invoke it. The tool will now succeed
		// because GetCredential will find the stored token.
		for _, ar := range authResponses {
			originalCall := findOriginalToolCall(events, ar.callID)
			if originalCall == nil {
				continue
			}

			// Re-run the original tool by synthesizing a FunctionCall event.
			// handleFunctionCalls will execute the tool and yield the result.
			ev, err := f.handleFunctionCalls(ctx, toolsmap, &model.LLMResponse{
				Content: &genai.Content{
					Parts: []*genai.Part{{FunctionCall: originalCall}},
					Role:  genai.RoleUser,
				},
			}, nil, nil)
			if !yield(ev, err) {
				return
			}
		}
	}
}

// findOriginalToolCall searches session events (newest first) for the FunctionCall that
// matches the given ID. The ID links the auth callback to its originating tool call:
// when a tool (e.g. get_user_info) requests credentials, the adk_request_credential
// FunctionCall reuses the original tool's call ID, so we can trace back from the OAuth
// callback to the tool that needs re-invocation. adk_request_credential calls themselves
// are skipped since we need the actual tool call (get_user_info, not adk_request_credential).
func findOriginalToolCall(events []*session.Event, functionCallID string) *genai.FunctionCall {
	for k := len(events) - 1; k >= 0; k-- {
		calls := utils.FunctionCalls(events[k].Content)
		for _, fc := range calls {
			if fc.ID == functionCallID && fc.Name != toolauth.FunctionCallName {
				return fc
			}
		}
	}
	return nil
}

func nlPlanningResponseProcessor(ctx agent.InvocationContext, req *model.LLMRequest, resp *model.LLMResponse) error {
	// TODO: implement (adk-python src/google/adk/_nl_planning.py)
	return nil
}

func codeExecutionResponseProcessor(ctx agent.InvocationContext, req *model.LLMRequest, resp *model.LLMResponse) error {
	// TODO: implement (adk-python src/google/adk_code_execution.py)
	return nil
}
