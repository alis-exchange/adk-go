// Copyright 2026 Google LLC
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

type authRequiredProcessor struct {
	reqCtx *a2asrv.RequestContext
	event  *a2a.TaskStatusUpdateEvent
}

func newAuthRequiredProcessor(reqCtx *a2asrv.RequestContext) *authRequiredProcessor {
	return &authRequiredProcessor{reqCtx: reqCtx}
}

// process handles auth-required events signaled via StateDelta (adk_auth_request_* keys).
// If the event indicates auth is required, sets p.event to TaskStateAuthRequired.
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
