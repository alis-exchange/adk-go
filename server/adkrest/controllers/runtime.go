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
	"log"
	"maps"
	"net/http"
	"time"

	"google.golang.org/genai"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/artifact"
	"google.golang.org/adk/memory"
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
		transformLegacyAuthEvent(event)
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

	opts := runOptions(runAgentRequest)
	resp := r.Run(ctx, runAgentRequest.UserId, runAgentRequest.SessionId, msg, *rCfg, opts...)

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
func (c *RuntimeAPIController) RunSSEHandler(rw http.ResponseWriter, req *http.Request) {
	// set custom deadlines for this request - it overrides server-wide timeouts
	rc := http.NewResponseController(rw)
	deadline := time.Now().Add(c.sseTimeout)
	err := rc.SetWriteDeadline(deadline)
	if err != nil {
		http.Error(rw, "failed to set write deadline: "+err.Error(), http.StatusInternalServerError)
		return
	}

	runAgentRequest, err := decodeRequestBody(req)
	if err != nil {
		http.Error(rw, "failed to decode request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	err = c.validateSessionExists(req.Context(), runAgentRequest.AppName, runAgentRequest.UserId, runAgentRequest.SessionId)
	if err != nil {
		http.Error(rw, "failed to find the session: "+err.Error(), http.StatusNotFound)
		return
	}

	msg := &runAgentRequest.NewMessage
	if runAgentRequest.AuthCallbackUrl != "" {
		if transformed := c.transformAuthCallback(req.Context(), runAgentRequest); transformed != nil {
			msg = transformed
		}
	}

	r, rCfg, err := c.getRunner(runAgentRequest)
	if err != nil {
		http.Error(rw, "failed to get runner: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Flush as soon as possible so the client doesn't drop connection.
	// Add the headers after the error handling to avoid wrong content type.
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	if err := rc.Flush(); err != nil {
		http.Error(rw, "failed to flush headers", http.StatusInternalServerError)
		return
	}

	opts := runOptions(runAgentRequest)
	resp := r.Run(req.Context(), runAgentRequest.UserId, runAgentRequest.SessionId, msg, *rCfg, opts...)

	for event, err := range resp {
		if err != nil {
			err := flashErrorEvent(rc, rw, err)
			// The error is returned only when we cannot communicate with the client
			// Exit the handler as connection is closed.
			if err != nil {
				log.Printf("failed to flash error event: %v", err)
				return
			}
			continue
		}
		if event == nil {
			continue
		}
		transformLegacyAuthEvent(event)
		// Skip reporting error if it fails to marshal to the client (to avoid recursive error reporting).
		marshalledData, err := json.Marshal(models.FromSessionEvent(*event))
		if err != nil {
			log.Printf("failed to marshal event: %v", err)
			return
		}
		err = flashEvent(rc, rw, string(marshalledData))
		if err != nil {
			log.Printf("failed to flash event: %v", err)
			return
		}
	}
}

func runOptions(req models.RunAgentRequest) []runner.RunOption {
	if req.StateDelta == nil {
		return nil
	}
	return []runner.RunOption{runner.WithStateDelta(*req.StateDelta)}
}

func flashErrorEvent(rc *http.ResponseController, rw http.ResponseWriter, origError error) error {
	_, err := fmt.Fprintf(rw, "event: error\n")
	if err != nil {
		return fmt.Errorf("write error event: %w", err)
	}
	safeErrorJSON, err := json.Marshal(map[string]string{"error": origError.Error()})
	if err != nil {
		// Skip reporting error if it fails to marshal to the client (to avoid recursive error reporting).
		return fmt.Errorf("marshal error event: %w", err)
	}
	return flashEvent(rc, rw, string(safeErrorJSON))
}

func flashEvent(rc *http.ResponseController, rw http.ResponseWriter, data string) error {
	_, err := fmt.Fprintf(rw, "data: %s\n\n", data)
	if err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	err = rc.Flush()
	if err != nil {
		return fmt.Errorf("flush event: %w", err)
	}
	return nil
}

func transformLegacyAuthEvent(event *session.Event) {
	if toolauth.IsAuthRequiredInStateDelta(event.Actions.StateDelta) {
		if fnCallID, authCfg, ok := toolauth.ExtractAuthRequestFromState(event.Actions.StateDelta); ok {
			content, longRunningIDs := toolauth.BuildAuthRequestContentFromConfig(fnCallID, authCfg)
			event.LLMResponse.Content = content
			event.LongRunningToolIDs = longRunningIDs
		}
	}
}

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
