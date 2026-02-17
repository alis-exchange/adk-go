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
	return func(yield func(*session.Event, error) bool) {
		toolsmap := make(map[string]tool.Tool)
		for _, t := range f.Tools {
			toolsmap[t.Name()] = t
		}

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

		for k := len(events) - 1; k >= 0; k-- {
			event := events[k]
			if event.Author != "user" {
				continue
			}
			responses := utils.FunctionResponses(event.Content)
			if len(responses) == 0 {
				return
			}
			for _, funcResp := range responses {
				if funcResp.Name != toolauth.FunctionCallName {
					continue
				}
				var cfg toolauth.AuthConfig
				if funcResp.Response != nil {
					var respMap map[string]any
					resp, hasResponseKey := funcResp.Response["response"]
					if hasResponseKey && len(funcResp.Response) == 1 {
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
						respMap = funcResp.Response
					}
					var err error
					cfg, err = toolauth.AuthConfigFromResponseMap(respMap)
					if err != nil {
						yield(nil, fmt.Errorf("auth preprocessor: %w", err))
						return
					}
				}
				if ctx.Session() != nil {
					if err := toolauth.ExchangeAndStore(ctx, cfg, ctx.Session().State()); err != nil {
						yield(nil, fmt.Errorf("auth preprocessor: exchange and store failed: %w", err))
						return
					}
				}
				authResponses = append(authResponses, authResp{cfg: cfg, callID: funcResp.ID})
			}
			break
		}

		if len(authResponses) == 0 {
			return
		}

		for _, ar := range authResponses {
			originalCall := findOriginalToolCall(events, ar.callID)
			if originalCall == nil {
				continue
			}

			ev, err := f.handleFunctionCalls(ctx, toolsmap, &model.LLMResponse{
				Content: &genai.Content{
					Parts: []*genai.Part{{FunctionCall: originalCall}},
					Role:  genai.RoleUser,
				},
			}, nil)
			if !yield(ev, err) {
				return
			}
		}
	}
}

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
