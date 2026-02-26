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

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"time"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/artifact"
	"google.golang.org/adk/memory"
	"google.golang.org/genai"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/server/adkrest/internal/models"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool/toolauth"
)

// RuntimeAPIController is the controller for the Runtime API.
type RuntimeAPIController struct {
	sseTimeout      time.Duration
	sessionService  session.Service
	memoryService   memory.Service
	artifactService artifact.Service
	agentLoader     agent.Loader
	pluginConfig    runner.PluginConfig
}

// NewRuntimeAPIController creates the controller for the Runtime API.
func NewRuntimeAPIController(sessionService session.Service, memoryService memory.Service, agentLoader agent.Loader, artifactService artifact.Service, sseTimeout time.Duration, pluginConfig runner.PluginConfig) *RuntimeAPIController {
	return &RuntimeAPIController{sessionService: sessionService, memoryService: memoryService, agentLoader: agentLoader, artifactService: artifactService, sseTimeout: sseTimeout, pluginConfig: pluginConfig}
}

// RunAgent executes a non-streaming agent run for a given session and message.
func (c *RuntimeAPIController) RunHandler(rw http.ResponseWriter, req *http.Request) error {
	runAgentRequest, err := decodeRequestBody(req)
	if err != nil {
		return err
	}
	sessionEvents, err := c.runAgent(req.Context(), runAgentRequest)
	if err != nil {
		return err
	}
	var events []models.Event
	for _, event := range sessionEvents {
		// Transform auth-required events: when a tool stored auth config in StateDelta,
		// replace the event's content with an adk_request_credential FunctionCall that
		// adk-web knows how to display (OAuth popup trigger).
		if toolauth.IsAuthRequired(event) {
			if fnCallID, authCfg, ok := toolauth.ExtractAuthRequest(event); ok {
				if authEvent := toolauth.BuildAuthRequestEvent(event, fnCallID, authCfg); authEvent != nil {
					event = authEvent
				}
			}
		}
		events = append(events, models.FromSessionEvent(*event))
	}
	EncodeJSONResponse(events, http.StatusOK, rw)
	return nil
}

// RunAgent executes a non-streaming agent run for a given session and message.
func (c *RuntimeAPIController) runAgent(ctx context.Context, runAgentRequest models.RunAgentRequest) ([]*session.Event, error) {
	err := c.validateSessionExists(ctx, runAgentRequest.AppName, runAgentRequest.UserId, runAgentRequest.SessionId)
	if err != nil {
		return nil, err
	}

	msg := &runAgentRequest.NewMessage
	if runAgentRequest.AuthCallbackUrl != "" {
		if transformed := c.transformAuthCallback(ctx, runAgentRequest); transformed != nil {
			msg = transformed
		}
	}

	r, rCfg, err := c.getRunner(runAgentRequest)
	if err != nil {
		return nil, err
	}

	resp := r.Run(ctx, runAgentRequest.UserId, runAgentRequest.SessionId, msg, *rCfg)

	var events []*session.Event
	for event, err := range resp {
		if err != nil {
			return nil, newStatusError(fmt.Errorf("failed to run agent: %w", err), http.StatusInternalServerError)
		}
		events = append(events, event)
	}
	return events, nil
}

// RunSSEHandler executes an agent run and streams the resulting events using Server-Sent Events (SSE).
func (c *RuntimeAPIController) RunSSEHandler(rw http.ResponseWriter, req *http.Request) error {
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")

	// set custom deadlines for this request - it overrides server-wide timeouts
	rc := http.NewResponseController(rw)
	deadline := time.Now().Add(c.sseTimeout)
	err := rc.SetWriteDeadline(deadline)
	if err != nil {
		return newStatusError(fmt.Errorf("failed to set write deadline: %w", err), http.StatusInternalServerError)
	}

	runAgentRequest, err := decodeRequestBody(req)
	if err != nil {
		return err
	}

	err = c.validateSessionExists(req.Context(), runAgentRequest.AppName, runAgentRequest.UserId, runAgentRequest.SessionId)
	if err != nil {
		return err
	}

	msg := &runAgentRequest.NewMessage
	if runAgentRequest.AuthCallbackUrl != "" {
		if transformed := c.transformAuthCallback(req.Context(), runAgentRequest); transformed != nil {
			msg = transformed
		}
	}

	r, rCfg, err := c.getRunner(runAgentRequest)
	if err != nil {
		return err
	}

	resp := r.Run(req.Context(), runAgentRequest.UserId, runAgentRequest.SessionId, msg, *rCfg)

	rw.WriteHeader(http.StatusOK)
	for event, err := range resp {
		if err != nil {
			_, err := fmt.Fprintf(rw, "Error while running agent: %v\n", err)
			if err != nil {
				return newStatusError(fmt.Errorf("failed to write response: %w", err), http.StatusInternalServerError)
			}
			err = rc.Flush()
			if err != nil {
				return newStatusError(fmt.Errorf("failed to flush: %w", err), http.StatusInternalServerError)
			}

			continue
		}
		// Transform auth-required events (StateDelta with adk_auth_request_*)
		// into adk_request_credential format for adk-web compatibility.
		if toolauth.IsAuthRequired(event) {
			if fnCallID, authCfg, ok := toolauth.ExtractAuthRequest(event); ok {
				if authEvent := toolauth.BuildAuthRequestEvent(event, fnCallID, authCfg); authEvent != nil {
					event = authEvent
				}
			}
		}
		err := flashEvent(rc, rw, *event)
		if err != nil {
			return err
		}
	}
	return nil
}

func flashEvent(rc *http.ResponseController, rw http.ResponseWriter, event session.Event) error {
	_, err := fmt.Fprintf(rw, "data: ")
	if err != nil {
		return newStatusError(fmt.Errorf("failed to write response: %w", err), http.StatusInternalServerError)
	}
	err = json.NewEncoder(rw).Encode(models.FromSessionEvent(event))
	if err != nil {
		return newStatusError(fmt.Errorf("failed to encode response: %w", err), http.StatusInternalServerError)
	}
	_, err = fmt.Fprintf(rw, "\n")
	if err != nil {
		return newStatusError(fmt.Errorf("failed to write response: %w", err), http.StatusInternalServerError)
	}
	err = rc.Flush()
	if err != nil {
		return newStatusError(fmt.Errorf("failed to flush: %w", err), http.StatusInternalServerError)
	}
	return nil
}

// transformAuthCallback converts an OAuth callback URL into a genai.Content message that
// authPreprocessor can process. This bridges the gap between the adk-web client (which sends
// the callback URL as a simple authCallbackUrl field) and the internal auth protocol (which
// expects an adk_request_credential FunctionResponse).
//
// The flow:
//  1. adk-web completes OAuth and reloads with ?authCallbackUrl=<url with code>.
//  2. decodeRequestBody reads authCallbackUrl from the query param or request body.
//  3. This function fetches the session to find the pending auth request (stored in state
//     by the previous invocation's StateDelta).
//  4. Builds a FunctionResponse with the auth config + callback URL.
//  5. The runner processes this message through authPreprocessor which exchanges the code
//     for tokens and re-invokes the original tool.
//
// Returns nil if no pending auth request exists in session state (normal request path).
func (c *RuntimeAPIController) transformAuthCallback(ctx context.Context, req models.RunAgentRequest) *genai.Content {
	resp, err := c.sessionService.Get(ctx, &session.GetRequest{
		AppName:   req.AppName,
		UserID:    req.UserId,
		SessionID: req.SessionId,
	})
	if err != nil || resp.Session == nil {
		return nil
	}
	stateMap := maps.Collect(resp.Session.State().All())
	fnCallID, authCfg, ok := toolauth.ExtractAuthRequestFromState(stateMap)
	if !ok {
		return nil
	}
	return toolauth.BuildAuthCallbackContent(fnCallID, authCfg, req.AuthCallbackUrl)
}

func (c *RuntimeAPIController) validateSessionExists(ctx context.Context, appName, userID, sessionID string) error {
	_, err := c.sessionService.Get(ctx, &session.GetRequest{
		AppName:   appName,
		UserID:    userID,
		SessionID: sessionID,
	})
	if err != nil {
		return newStatusError(fmt.Errorf("failed to get session: %w", err), http.StatusNotFound)
	}
	return nil
}

func (c *RuntimeAPIController) getRunner(req models.RunAgentRequest) (*runner.Runner, *agent.RunConfig, error) {
	curAgent, err := c.agentLoader.LoadAgent(req.AppName)
	if err != nil {
		return nil, nil, newStatusError(fmt.Errorf("failed to load agent: %w", err), http.StatusInternalServerError)
	}

	r, err := runner.New(runner.Config{
		AppName:         req.AppName,
		Agent:           curAgent,
		SessionService:  c.sessionService,
		MemoryService:   c.memoryService,
		ArtifactService: c.artifactService,
		PluginConfig:    c.pluginConfig,
	},
	)
	if err != nil {
		return nil, nil, newStatusError(fmt.Errorf("failed to create runner: %w", err), http.StatusInternalServerError)
	}

	streamingMode := agent.StreamingModeNone
	if req.Streaming {
		streamingMode = agent.StreamingModeSSE
	}
	return r, &agent.RunConfig{
		StreamingMode: streamingMode,
	}, nil
}

// decodeRequestBody reads, normalizes, and parses the RunAgentRequest from an HTTP request.
//
// Two normalization steps are applied before decoding:
//
//  1. normalizeNewMessageParts converts snake_case part keys to camelCase. This is needed
//     because adk-web's JavaScript sends "function_response" and "function_call" but
//     genai.Part's JSON tags expect "functionResponse" and "functionCall".
//
//  2. authCallbackUrl can be provided via query parameter (?authCallbackUrl=...) as a
//     fallback. This supports the OAuth redirect flow where the browser reloads the page
//     and the callback URL may not be in the JSON body.
func decodeRequestBody(req *http.Request) (decodedReq models.RunAgentRequest, err error) {
	var runAgentRequest models.RunAgentRequest
	defer func() {
		_ = req.Body.Close()
	}()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return runAgentRequest, newStatusError(fmt.Errorf("failed to read request body: %w", err), http.StatusBadRequest)
	}
	body = normalizeNewMessageParts(body)
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&runAgentRequest); err != nil {
		return runAgentRequest, newStatusError(fmt.Errorf("failed to decode request: %w", err), http.StatusBadRequest)
	}
	if q := req.URL.Query().Get("authCallbackUrl"); q != "" && runAgentRequest.AuthCallbackUrl == "" {
		runAgentRequest.AuthCallbackUrl = q
	}
	return runAgentRequest, nil
}

// normalizeNewMessageParts fixes a serialization mismatch between adk-web and the Go genai SDK.
// adk-web's JavaScript sends message parts with snake_case keys ("function_response",
// "function_call") because the Python protobuf JSON serialization uses that convention.
// However, genai.Part in Go uses camelCase JSON tags ("functionResponse", "functionCall").
// This function rewrites the keys in-place before JSON decoding to bridge the two conventions.
func normalizeNewMessageParts(body []byte) []byte {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	newMsg, _ := raw["newMessage"].(map[string]any)
	if newMsg == nil {
		return body
	}
	parts, _ := newMsg["parts"].([]any)
	if len(parts) == 0 {
		return body
	}
	for _, p := range parts {
		part, _ := p.(map[string]any)
		if part == nil {
			continue
		}
		if v, has := part["function_response"]; has && part["functionResponse"] == nil {
			part["functionResponse"] = v
			delete(part, "function_response")
		}
		if v, has := part["function_call"]; has && part["functionCall"] == nil {
			part["functionCall"] = v
			delete(part, "function_call")
		}
	}
	normalized, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return normalized
}
