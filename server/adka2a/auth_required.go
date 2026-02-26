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
// ## How It Fits in the A2A Flow
//
// When a tool calls RequestCredential and no stored token exists, the tool returns "Pending
// User Authorization" and the CredentialHelper stores the auth config in the event's StateDelta
// under "adk_auth_request_<functionCallID>". During event processing (in eventProcessor.process),
// this processor checks each event for those StateDelta keys.
//
// If an auth request is found, the processor:
//  1. Extracts the functionCallID and AuthConfig from StateDelta.
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

// process checks if the event contains an auth request in StateDelta. If found, builds
// the adk_request_credential content and stores a TaskStateAuthRequired event. The original
// event is returned unchanged so downstream processors (inputRequired, artifact conversion)
// can still inspect it.
func (p *authRequiredProcessor) process(event *session.Event) (*session.Event, error) {
	if !toolauth.IsAuthRequired(event) {
		return event, nil
	}
	functionCallID, authConfig, ok := toolauth.ExtractAuthRequest(event)
	if !ok {
		return event, nil
	}
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
