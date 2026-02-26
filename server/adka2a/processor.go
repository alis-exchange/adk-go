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
	"context"
	"fmt"
	"maps"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"

	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
)

// eventProcessor converts ADK session events into A2A protocol events (artifacts and status
// updates). It processes events one at a time, accumulating terminal states that are emitted
// at the end via makeFinalStatusUpdate.
//
// ## Processing Pipeline
//
// Each event passes through this sequence:
//  1. updateTerminalActions: tracks escalation and agent-transfer actions across all events.
//  2. Error check: if the LLM response contains an error, a failedEvent is recorded.
//  3. authRequiredProcessor: checks for auth requests in StateDelta (adk_auth_request_*).
//  4. inputRequiredProcessor: checks for long-running tool calls (LongRunningToolIDs).
//  5. Part conversion: converts genai.Parts to A2A-native parts for artifact updates.
//
// ## Terminal Status Priority
//
// Multiple terminal conditions can be detected during a single invocation. The final status
// is determined by priority: failed > authRequired > inputRequired > completed. This ensures
// that errors always surface, auth requirements take precedence over input requirements
// (since auth must be resolved before the tool can produce meaningful output), and completed
// is only used when no other terminal condition was detected.
type eventProcessor struct {
	reqCtx        *a2asrv.RequestContext
	meta          invocationMeta
	partConverter GenAIPartConverter

	// terminalActions tracks escalate and agent transfer actions across all processed events.
	// Attached to the final terminal event's metadata so the caller can act on them, since
	// intermediate events without parts may be skipped.
	terminalActions session.EventActions

	// responseID is created once the first TaskArtifactUpdateEvent is sent. Used for subsequent artifact updates.
	responseID a2a.ArtifactID
	// partialResponseID is created once the first TaskArtifactUpdateEvent created from a partial ADK event is sent.
	// Partial updates are not saved in the ADK session store. There is no concept of a partial event in A2A so instead
	// we're updating an "ephemeral" artifact while an agent is running. The artifact gets reset at the end of the
	// invocation effectively erasing its parts.
	partialResponseID a2a.ArtifactID

	// failedEvent records an LLM error. Highest priority terminal state.
	failedEvent *a2a.TaskStatusUpdateEvent

	// authRequiredProcessor detects tool auth requests (StateDelta with adk_auth_request_*).
	// Its event, if set, is the second-highest priority terminal state.
	authRequiredProcessor *authRequiredProcessor

	// inputRequiredProcessor detects long-running tool calls that need user input.
	// Its event, if set, is the third-highest priority terminal state.
	inputRequiredProcessor *inputRequiredProcessor
}

func newEventProcessor(
	reqCtx *a2asrv.RequestContext,
	meta invocationMeta,
	converter GenAIPartConverter,
) *eventProcessor {
	return &eventProcessor{
		authRequiredProcessor:  newAuthRequiredProcessor(reqCtx),
		inputRequiredProcessor: newInputRequiredProcessor(reqCtx),
		partConverter:          converter,
		reqCtx:                 reqCtx,
		meta:                   meta,
	}
}

func (p *eventProcessor) process(ctx context.Context, event *session.Event) (*a2a.TaskArtifactUpdateEvent, error) {
	if event == nil {
		return nil, nil
	}

	p.updateTerminalActions(event)

	eventMeta, err := toEventMeta(p.meta, event)
	if err != nil {
		return nil, err
	}

	resp := event.LLMResponse
	if resp.ErrorCode != "" || resp.ErrorMessage != "" {
		// TODO(yarolegovich): consider merging responses if multiple errors can be produced during an invocation
		if p.failedEvent == nil {
			// terminal event might add additional keys to its metadata when it's dispatched and these changes should
			// not be reflected in this event's metadata
			terminalEventMeta := maps.Clone(eventMeta)
			p.failedEvent = toTaskFailedUpdateEvent(p.reqCtx, errorFromResponse(&resp), terminalEventMeta)
		}
	}

	event, err = p.authRequiredProcessor.process(event)
	if err != nil {
		return nil, fmt.Errorf("auth required processing failed: %w", err)
	}
	event, err = p.inputRequiredProcessor.process(event)
	if err != nil {
		return nil, fmt.Errorf("input required processing failed: %w", err)
	}

	parts, err := p.convertParts(ctx, event)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, nil
	}

	var result *a2a.TaskArtifactUpdateEvent
	if event.Partial {
		result = newPartialArtifactUpdate(p.reqCtx, p.partialResponseID, parts)
		p.partialResponseID = result.Artifact.ID
	} else {
		result = newArtifactUpdate(p.reqCtx, p.responseID, parts)
		p.responseID = result.Artifact.ID
	}

	if len(eventMeta) > 0 {
		maps.Copy(result.Metadata, eventMeta)
	}

	return result, nil
}

func newArtifactUpdate(task a2a.TaskInfoProvider, id a2a.ArtifactID, parts []a2a.Part) *a2a.TaskArtifactUpdateEvent {
	var result *a2a.TaskArtifactUpdateEvent
	if id == "" {
		result = a2a.NewArtifactEvent(task, parts...)
	} else {
		result = a2a.NewArtifactUpdateEvent(task, id, parts...)
	}
	// Explicitely mark and Artifact update as non-partial ADK event so that consumer side
	// does not run its own aggregation logic.
	result.Metadata = map[string]any{metadataPartialKey: false}
	return result
}

func newPartialArtifactUpdate(task a2a.TaskInfoProvider, artifactID a2a.ArtifactID, parts []a2a.Part) *a2a.TaskArtifactUpdateEvent {
	ev := newArtifactUpdate(task, artifactID, parts)
	updatePartsMetadata(parts, map[string]any{metadataPartialKey: true})
	if ev.Artifact.Metadata == nil {
		ev.Artifact.Metadata = map[string]any{metadataPartialKey: true}
	} else {
		ev.Artifact.Metadata[metadataPartialKey] = true
	}
	ev.Metadata[metadataPartialKey] = true
	ev.Append = false // discard partial events
	return ev
}

func (p *eventProcessor) makeFinalArtifactUpdate() *a2a.TaskArtifactUpdateEvent {
	// We could also send a LastChunk: true event for the main (non-partial) artifact,
	// but there's currently no special handling for it and not all A2A SDK (eg. Java)
	// implementations allow empty-part artifact updates.
	if p.partialResponseID == "" {
		return nil
	}
	ev := newPartialArtifactUpdate(p.reqCtx, p.partialResponseID, []a2a.Part{a2a.DataPart{Data: map[string]any{}}})
	ev.LastChunk = true
	return ev
}

// makeFinalStatusUpdate returns the terminal status update for the A2A task. This is called
// once after all events have been processed. The priority order ensures correct behavior:
//   - failed: LLM returned an error; the task cannot continue.
//   - authRequired: a tool needs OAuth credentials; the client should open the auth popup.
//   - inputRequired: a long-running tool needs user input before completing.
//   - completed: all tools ran successfully and the agent produced a final response.
func (p *eventProcessor) makeFinalStatusUpdate() *a2a.TaskStatusUpdateEvent {
	for _, event := range []*a2a.TaskStatusUpdateEvent{p.failedEvent, p.authRequiredProcessor.event, p.inputRequiredProcessor.event} {
		if event != nil {
			event.Metadata = setActionsMeta(event.Metadata, p.terminalActions)
			return event
		}
	}

	ev := a2a.NewStatusUpdateEvent(p.reqCtx, a2a.TaskStateCompleted, nil)
	ev.Final = true
	// we're modifying base processor metadata which might have been sent with one of the previous events.
	// this update shouldn't be reflected in the sent events' metadata.
	baseMetaCopy := maps.Clone(p.meta.eventMeta)
	ev.Metadata = setActionsMeta(baseMetaCopy, p.terminalActions)
	return ev
}

func (p *eventProcessor) makeTaskFailedEvent(cause error, event *session.Event) *a2a.TaskStatusUpdateEvent {
	meta := p.meta.eventMeta
	if event != nil {
		if eventMeta, err := toEventMeta(p.meta, event); err != nil {
			// TODO(yarolegovich): log ignored error
		} else {
			meta = eventMeta
		}
	}
	return toTaskFailedUpdateEvent(p.reqCtx, cause, meta)
}

func (p *eventProcessor) updateTerminalActions(event *session.Event) {
	p.terminalActions.Escalate = p.terminalActions.Escalate || event.Actions.Escalate
	if event.Actions.TransferToAgent != "" {
		p.terminalActions.TransferToAgent = event.Actions.TransferToAgent
	}
}

func (p *eventProcessor) convertParts(ctx context.Context, event *session.Event) ([]a2a.Part, error) {
	if event.Content == nil || len(event.Content.Parts) == 0 {
		return nil, nil
	}
	parts := event.Content.Parts
	if p.partConverter == nil {
		return ToA2AParts(parts, event.LongRunningToolIDs)
	}
	converted := make([]a2a.Part, 0, len(parts))
	for _, part := range parts {
		cp, err := p.partConverter(ctx, event, part)
		if err != nil {
			return nil, err
		}
		if cp == nil {
			continue
		}
		converted = append(converted, cp)
	}
	return converted, nil
}

func toTaskFailedUpdateEvent(task a2a.TaskInfoProvider, cause error, meta map[string]any) *a2a.TaskStatusUpdateEvent {
	msg := a2a.NewMessageForTask(a2a.MessageRoleAgent, task, a2a.TextPart{Text: cause.Error()})
	ev := a2a.NewStatusUpdateEvent(task, a2a.TaskStateFailed, msg)
	ev.Metadata = meta
	ev.Final = true
	return ev
}

func errorFromResponse(resp *model.LLMResponse) error {
	return fmt.Errorf("llm error response: %q", resp.ErrorMessage)
}
