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
	"log"

	"google.golang.org/genai"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/internal/utils"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/toolauth"
)

func identityRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	// TODO: implement (adk-python src/google/adk/flows/llm_flows/identity.py)
	return func(yield func(*session.Event, error) bool) {}
}

func nlPlanningRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	// TODO: implement (adk-python src/google/adk/flows/llm_flows/_nl_plnning.py)
	return func(yield func(*session.Event, error) bool) {}
}

func codeExecutionRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	// TODO: implement (adk-python src/google/adk/flows/llm_flows/_code_execution.py)
	return func(yield func(*session.Event, error) bool) {}
}

func authPreprocessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	invID := ctx.InvocationID()
	log.Printf("[authPreprocessor][%s] STEP 1: entered", invID)

	return func(yield func(*session.Event, error) bool) {
		toolsmap := make(map[string]tool.Tool)
		for _, t := range f.Tools {
			toolsmap[t.Name()] = t
		}
		log.Printf("[authPreprocessor][%s] STEP 2: tools loaded, count=%d, names=%v", invID, len(toolsmap), mapKeys(toolsmap))

		var events []*session.Event
		if ctx.Session() != nil {
			for e := range ctx.Session().Events().All() {
				log.Printf("[authPreprocessor][%s] STEP 3: event id=%s author=%s parts=%d", invID, e.ID, e.Author, len(e.Content.Parts))
				for i, part := range e.Content.Parts {
					if part.FunctionResponse != nil {
						log.Printf("[authPreprocessor][%s]   part[%d] FunctionResponse name=%s id=%s", invID, i, part.FunctionResponse.Name, part.FunctionResponse.ID)
					}
					if part.FunctionCall != nil {
						log.Printf("[authPreprocessor][%s]   part[%d] FunctionCall name=%s id=%s", invID, i, part.FunctionCall.Name, part.FunctionCall.ID)
					}
				}
				events = append(events, e)
			}
		} else {
			log.Printf("[authPreprocessor][%s] STEP 3: session is nil, skipping events", invID)
		}
		log.Printf("[authPreprocessor][%s] STEP 4: total events=%d", invID, len(events))

		type authResp struct {
			cfg    toolauth.AuthConfig
			callID string
		}
		var authResponses []authResp

		for k := len(events) - 1; k >= 0; k-- {
			event := events[k]
			log.Printf("[authPreprocessor][%s] STEP 5: examining event[%d] id=%s author=%s", invID, k, event.ID, event.Author)
			if event.Author != "user" {
				log.Printf("[authPreprocessor][%s]   skip: author!=user", invID)
				continue
			}
			responses := utils.FunctionResponses(event.Content)
			log.Printf("[authPreprocessor][%s]   FunctionResponses count=%d", invID, len(responses))
			if len(responses) == 0 {
				continue
			}
			for _, funcResp := range responses {
				log.Printf("[authPreprocessor][%s] STEP 6: funcResp name=%s id=%s (expect %s)", invID, funcResp.Name, funcResp.ID, toolauth.FunctionCallName)
				if funcResp.Name != toolauth.FunctionCallName {
					log.Printf("[authPreprocessor][%s]   skip: name mismatch", invID)
					continue
				}
				log.Printf("[authPreprocessor][%s] STEP 7: found adk_request_credential response", invID)
				var cfg toolauth.AuthConfig
				if funcResp.Response != nil {
					var respMap map[string]any
					resp, hasResponseKey := funcResp.Response["response"]
					log.Printf("[authPreprocessor][%s] STEP 8: parsing response hasResponseKey=%v responseKeys=%v", invID, hasResponseKey, mapKeysAny(funcResp.Response))
					if hasResponseKey && len(funcResp.Response) == 1 {
						if jsonString, ok := resp.(string); ok {
							if err := json.Unmarshal([]byte(jsonString), &respMap); err != nil {
								log.Printf("[authPreprocessor][%s] STEP 8 ERROR: unmarshal failed: %v", invID, err)
								yield(nil, fmt.Errorf("auth preprocessor: failed to unmarshal auth response for event %q: %w", event.ID, err))
								return
							}
							log.Printf("[authPreprocessor][%s]   unmarshaled from JSON string, respMap keys=%v", invID, mapKeysAny(respMap))
						} else if m, ok := resp.(map[string]any); ok {
							respMap = m
							log.Printf("[authPreprocessor][%s]   response was map directly", invID)
						} else {
							log.Printf("[authPreprocessor][%s] STEP 8 ERROR: response key value type=%T not string or object", invID, resp)
							yield(nil, fmt.Errorf("auth preprocessor: response key value is not string or object for event %q", event.ID))
							return
						}
					} else {
						respMap = funcResp.Response
						log.Printf("[authPreprocessor][%s]   using funcResp.Response directly, keys=%v", invID, mapKeysAny(respMap))
					}
					var err error
					cfg, err = toolauth.AuthConfigFromResponseMap(respMap)
					if err != nil {
						log.Printf("[authPreprocessor][%s] STEP 9 ERROR: AuthConfigFromResponseMap: %v", invID, err)
						yield(nil, fmt.Errorf("auth preprocessor: %w", err))
						return
					}
					log.Printf("[authPreprocessor][%s] STEP 9: AuthConfig parsed credential_key=%s", invID, cfg.CredentialKey)
				} else {
					log.Printf("[authPreprocessor][%s] STEP 8: funcResp.Response is nil", invID)
				}
				if ctx.Session() != nil {
					log.Printf("[authPreprocessor][%s] STEP 10: calling ExchangeAndStore", invID)
					if err := toolauth.ExchangeAndStore(ctx, cfg, ctx.Session().State()); err != nil {
						log.Printf("[authPreprocessor][%s] STEP 10 ERROR: ExchangeAndStore: %v", invID, err)
						yield(nil, fmt.Errorf("auth preprocessor: exchange and store failed: %w", err))
						return
					}
					log.Printf("[authPreprocessor][%s] STEP 10: ExchangeAndStore succeeded", invID)
				}
				authResponses = append(authResponses, authResp{cfg: cfg, callID: funcResp.ID})
				log.Printf("[authPreprocessor][%s] STEP 11: appended authResponse callID=%s", invID, funcResp.ID)
				break
			}
		}

		log.Printf("[authPreprocessor][%s] STEP 12: authResponses count=%d", invID, len(authResponses))
		if len(authResponses) == 0 {
			log.Printf("[authPreprocessor][%s] STEP 12: early exit, no auth responses to process", invID)
			return
		}

		for i, ar := range authResponses {
			log.Printf("[authPreprocessor][%s] STEP 13: finding original tool call for authResponse[%d] callID=%s", invID, i, ar.callID)
			originalCall := findOriginalToolCall(events, ar.callID)
			if originalCall == nil {
				log.Printf("[authPreprocessor][%s]   originalCall not found, skipping", invID)
				continue
			}
			log.Printf("[authPreprocessor][%s] STEP 14: found originalCall name=%s id=%s, invoking handleFunctionCalls", invID, originalCall.Name, originalCall.ID)

			ev, err := f.handleFunctionCalls(ctx, toolsmap, &model.LLMResponse{
				Content: &genai.Content{
					Parts: []*genai.Part{{FunctionCall: originalCall}},
					Role:  genai.RoleUser,
				},
			}, nil)
			if err != nil {
				log.Printf("[authPreprocessor][%s] STEP 14 ERROR: handleFunctionCalls: %v", invID, err)
			} else {
				log.Printf("[authPreprocessor][%s] STEP 14: handleFunctionCalls succeeded", invID)
			}
			if !yield(ev, err) {
				return
			}
		}
		log.Printf("[authPreprocessor][%s] STEP 15: done", invID)
	}
}

func mapKeys(m map[string]tool.Tool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func mapKeysAny(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func findOriginalToolCall(events []*session.Event, functionCallID string) *genai.FunctionCall {
	log.Printf("[findOriginalToolCall] searching for functionCallID=%s (excluding %s)", functionCallID, toolauth.FunctionCallName)
	for k := len(events) - 1; k >= 0; k-- {
		calls := utils.FunctionCalls(events[k].Content)
		for _, fc := range calls {
			if fc.ID == functionCallID && fc.Name != toolauth.FunctionCallName {
				log.Printf("[findOriginalToolCall] found at event[%d]: name=%s id=%s", k, fc.Name, fc.ID)
				return fc
			}
		}
	}
	log.Printf("[findOriginalToolCall] not found for functionCallID=%s", functionCallID)
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
