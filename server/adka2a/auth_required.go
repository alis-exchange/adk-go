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

package adka2a

import (
	"fmt"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"

	"google.golang.org/adk/session"
	"google.golang.org/adk/tool/toolauth"
)

// authRequiredProcessor detects tool auth requests during A2A event processing and converts
// them into A2A-native TaskStateAuthRequired status updates.
//
// ## Detection Strategy (dual-path)
//
// The processor uses two detection paths, checked in order:
//
//  1. Primary: EventActions.RequestedAuthConfigs -- populated by tools that use
//     toolCtx.RequestCredential(cfg). The LLM flow layer (generateAuthEvent) also
//     generates an auth event from this field, but the A2A processor still checks it
//     to produce the A2A-native TaskStateAuthRequired status update.
//
//  2. Fallback: EventActions.StateDelta with "adk_auth_request_" prefix -- the legacy path
//     where tools stored auth configs via CredentialHelper. Retained for backward
//     compatibility with existing tools.
//
// ## How It Fits in the A2A Flow
//
// If an auth request is found (from either path), the processor:
//  1. Extracts the functionCallID and AuthConfig.
//  2. Calls BuildAuthRequestContentFromConfig to generate the adk_request_credential FunctionCall
//     content with the OAuth URL.
//  3. Converts the genai parts to A2A-native parts.
//  4. Wraps them in a TaskStatusUpdateEvent with state=auth-required and final=true.
//
// The stored event (p.event) is later used by makeFinalStatusUpdate as the terminal status
// for the A2A task. The A2A client receives this, opens the OAuth popup, and upon completion
// sends the callback via sendStreamingMessage which flows through the A2A event conversion
// layer and eventually reaches authPreprocessor for token exchange.
type authRequiredProcessor struct {
	reqCtx *a2asrv.RequestContext
	event  *a2a.TaskStatusUpdateEvent
}

func newAuthRequiredProcessor(reqCtx *a2asrv.RequestContext) *authRequiredProcessor {
	return &authRequiredProcessor{reqCtx: reqCtx}
}

// process checks if the event contains an auth request. It checks
// EventActions.RequestedAuthConfigs first (new path), then falls back to
// StateDelta scanning (legacy path). If found, builds the adk_request_credential
// content and stores a TaskStateAuthRequired event. The original event is returned
// unchanged so downstream processors (inputRequired, artifact conversion) can
// still inspect it.
func (p *authRequiredProcessor) process(event *session.Event) (*session.Event, error) {
	var functionCallID string
	var authConfig toolauth.AuthConfig
	var found bool

	// Primary path: check RequestedAuthConfigs populated by toolCtx.RequestCredential.
	if len(event.Actions.RequestedAuthConfigs) > 0 {
		for id, cfg := range event.Actions.RequestedAuthConfigs {
			functionCallID = id
			authConfig = cfg
			found = true
			break
		}
	}

	// Fallback path: check StateDelta for legacy "adk_auth_request_" keys.
	if !found {
		if !toolauth.IsAuthRequiredInStateDelta(event.Actions.StateDelta) {
			return event, nil
		}
		functionCallID, authConfig, found = toolauth.ExtractAuthRequestFromState(event.Actions.StateDelta)
		if !found {
			return event, nil
		}
	}

	// Build the adk_request_credential FunctionCall content with the OAuth URL
	// and convert to A2A-native parts for the TaskStatusUpdateEvent.
	authContent, longRunningIDs := toolauth.BuildAuthRequestContentFromConfig(functionCallID, authConfig)
	a2aParts, err := ToA2AParts(authContent.Parts, longRunningIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert auth required parts to A2A parts: %w", err)
	}
	msg := a2a.NewMessage(a2a.MessageRoleAgent, a2aParts...)
	ev := a2a.NewStatusUpdateEvent(p.reqCtx, a2a.TaskStateAuthRequired, msg)
	ev.Final = true
	p.event = ev
	return event, nil
}
