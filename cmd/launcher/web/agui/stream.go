package agui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/encoding/sse"
	"github.com/google/uuid"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool/toolconfirmation"
	"google.golang.org/genai"
)

// bufPool reuses byte buffers for JSON serialization on the event-emission hot path.
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// TODO: Remove interruptOutcome and interrupt once the AG-UI Go SDK adds
// typed Outcome/Interrupt structs to its events and types packages.
//
// interruptOutcome is the AG-UI RunFinished outcome for interrupt-aware runs.
// See https://docs.ag-ui.com/concepts/interrupts#run-outcomes
type interruptOutcome struct {
	Type       string      `json:"type"`
	Interrupts []interrupt `json:"interrupts"`
}

// interrupt describes a single pause point requiring user input.
// See https://docs.ag-ui.com/concepts/interrupts#the-interrupt-type
type interrupt struct {
	ID             string         `json:"id"`
	Reason         string         `json:"reason"`
	Message        string         `json:"message,omitempty"`
	ToolCallID     string         `json:"toolCallId,omitempty"`
	ResponseSchema map[string]any `json:"responseSchema,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// TODO: Remove runFinishedInterruptEvent once the AG-UI Go SDK adds an
// Outcome field to RunFinishedEvent; use the SDK type directly instead.
//
// runFinishedInterruptEvent extends RunFinished with the outcome field required
// by the AG-UI interrupt protocol. The community Go SDK's RunFinishedEvent does
// not yet have an Outcome field, so we define a local event type that includes it.
type runFinishedInterruptEvent struct {
	*events.BaseEvent
	ThreadIDValue string            `json:"threadId"`
	RunIDValue    string            `json:"runId"`
	Outcome       *interruptOutcome `json:"outcome,omitempty"`
}

func (e *runFinishedInterruptEvent) ThreadID() string        { return e.ThreadIDValue }
func (e *runFinishedInterruptEvent) RunID() string           { return e.RunIDValue }
func (e *runFinishedInterruptEvent) ToJSON() ([]byte, error) { return json.Marshal(e) }

func (e *runFinishedInterruptEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.ThreadIDValue == "" {
		return fmt.Errorf("runFinishedInterruptEvent: threadId is required")
	}
	if e.RunIDValue == "" {
		return fmt.Errorf("runFinishedInterruptEvent: runId is required")
	}
	if e.Outcome == nil || len(e.Outcome.Interrupts) == 0 {
		return fmt.Errorf("runFinishedInterruptEvent: outcome with at least one interrupt is required")
	}
	return nil
}

// emitter wraps the SSE writer and captures the first write error. After a
// failure (typically a client disconnect), subsequent emit calls are no-ops.
// This avoids per-call error checks while still stopping work promptly.
//
// When interceptors are configured, each event passes through the OnEmit chain
// (in registration order) before being written. An interceptor may transform
// the event, suppress it (return nil), or abort the stream (return an error).
type emitter struct {
	ctx          context.Context
	w            http.ResponseWriter
	writer       *sse.SSEWriter
	err          error
	interceptors []CallInterceptor
	callCtx      *CallContext
}

func newEmitter(ctx context.Context, w http.ResponseWriter, writer *sse.SSEWriter, interceptors []CallInterceptor, callCtx *CallContext) *emitter {
	return &emitter{ctx: ctx, w: w, writer: writer, interceptors: interceptors, callCtx: callCtx}
}

func (e *emitter) emit(event events.Event) {
	if e.err != nil {
		return
	}
	for _, interceptor := range e.interceptors {
		var err error
		event, err = interceptor.OnEmit(e.ctx, e.callCtx, event)
		if err != nil {
			e.err = err
			return
		}
		if event == nil {
			return
		}
	}
	e.err = e.writer.WriteEvent(e.ctx, e.w, event)
}

// streamState tracks the AG-UI event state machine across the SSE stream.
// It manages open text messages, reasoning phases, sub-agent steps, and
// ensures proper lifecycle event ordering (start/content/end).
//
// Fields are ordered largest-first (strings before bools) to minimize struct padding.
type streamState struct {
	runID                     string // AG-UI run identifier
	threadID                  string // AG-UI thread identifier; also used as ADK session ID
	currentTextMessageID      string // active text message, empty when none open
	currentReasoningPhaseID   string // active reasoning phase (ReasoningStart/End), empty when none open
	currentReasoningMessageID string // active reasoning message within the phase, empty when none open
	lastTextMessageID         string // most recent closed text message, used as parentMessageID for tool calls
	currentStepAuthor         string // active sub-agent step, empty when at root agent
	runFinalized              bool   // true once RunFinished or RunError has been emitted
}

// processEvent maps a single ADK session.Event to the corresponding AG-UI SSE events.
// It manages three state machines:
//   - Text streaming: TextMessageStart -> TextMessageContent* -> TextMessageEnd
//   - Reasoning: ReasoningStart -> ReasoningMessageStart -> ReasoningMessageContent* -> ReasoningMessageEnd -> ReasoningEnd
//   - Sub-agent steps: StepStarted -> StepFinished (triggered by Author changes)
//
// Tool calls are emitted atomically (Start+Args+End) because ADK provides
// complete function call args in a single event, not incrementally.
//
// Returns (done, err). When done is true the run has been finalized (e.g. an
// interrupt was emitted) and the caller should stop processing events.
func (l *aguiLauncher) processEvent(e *emitter, ev *session.Event, state *streamState) (bool, error) {
	// Emit step events when the active sub-agent changes.
	// Root agent (l.config.appName) doesn't get step events.
	if ev.Author != "" && ev.Author != state.currentStepAuthor {
		if state.currentStepAuthor != "" {
			e.emit(events.NewStepFinishedEvent(state.currentStepAuthor))
		}
		if ev.Author != l.config.appName {
			e.emit(events.NewStepStartedEvent(ev.Author))
			state.currentStepAuthor = ev.Author
		} else {
			state.currentStepAuthor = ""
		}
	}

	if ev.Content != nil {
		for _, part := range ev.Content.Parts {
			if e.err != nil {
				return false, e.err
			}
			if part == nil {
				continue
			}

			// Let the consumer's part converter handle the part first.
			// A non-nil return (even empty) means "handled, skip default".
			if l.config.genAIPartConverter != nil {
				customEvents, err := l.config.genAIPartConverter(e.ctx, ev, part)
				if err != nil {
					return false, fmt.Errorf("GenAIPartConverter: %w", err)
				}
				if customEvents != nil {
					for _, ce := range customEvents {
						e.emit(ce)
					}
					continue
				}
			}

			// Reasoning / thought parts: map to REASONING_* event lifecycle.
			// ReasoningStart/End bracket the phase; ReasoningMessageStart/Content/End
			// bracket individual messages within it. Per the AG-UI spec, these use
			// separate IDs.
			if part.Thought && part.Text != "" {
				closeTextMessage(e, state)

				if state.currentReasoningPhaseID == "" {
					state.currentReasoningPhaseID = events.GenerateMessageID()
					e.emit(events.NewReasoningStartEvent(state.currentReasoningPhaseID))
				}
				if state.currentReasoningMessageID == "" {
					state.currentReasoningMessageID = events.GenerateMessageID()
					e.emit(events.NewReasoningMessageStartEvent(state.currentReasoningMessageID, "reasoning"))
				}
				e.emit(events.NewReasoningMessageContentEvent(state.currentReasoningMessageID, part.Text))
				continue
			}

			// Text parts (non-thought): map to TEXT_MESSAGE_* event lifecycle.
			if part.Text != "" && !part.Thought {
				// Close any open reasoning message before emitting text.
				closeReasoningMessage(e, state)

				// ADK streaming emits partial events with delta text, then a final
				// non-partial event with the full accumulated text. Skip the final
				// event to avoid re-emitting text that was already streamed.
				if !ev.Partial {
					continue
				}

				if state.currentTextMessageID == "" {
					state.currentTextMessageID = events.GenerateMessageID()
					e.emit(events.NewTextMessageStartEvent(state.currentTextMessageID, events.WithRole("assistant")))
				}
				e.emit(events.NewTextMessageContentEvent(state.currentTextMessageID, part.Text))
				continue
			}

			// Function call handling. Two cases:
			//
			// 1. adk_request_confirmation: ADK's HITL wrapper. Convert to an
			//    AG-UI interrupt — emit ToolCall events for the *original* tool
			//    (the agent's proposal, per the "Tool-bound interrupts" audit
			//    trail spec), then emit RunFinished with an interrupt outcome.
			//
			// 2. All other function calls: emit ToolCallStart -> ToolCallArgs ->
			//    ToolCallEnd atomically. ADK provides complete args in a single
			//    FunctionCall (not streamed incrementally).
			if part.FunctionCall != nil {
				closeTextMessage(e, state)
				closeReasoningMessage(e, state)

				if part.FunctionCall.Name == toolconfirmation.FunctionCallName {
					if err := l.emitInterrupt(e, state, part.FunctionCall); err != nil {
						return false, err
					}
					return true, nil
				}

				// Link tool call to the preceding text message if one exists.
				var opts []events.ToolCallStartOption
				if state.lastTextMessageID != "" {
					opts = append(opts, events.WithParentMessageID(state.lastTextMessageID))
				}
				e.emit(events.NewToolCallStartEvent(part.FunctionCall.ID, part.FunctionCall.Name, opts...))

				argsJSON, err := marshalPooled(part.FunctionCall.Args)
				if err != nil {
					return false, fmt.Errorf("failed to marshal function call args: %w", err)
				}
				e.emit(events.NewToolCallArgsEvent(part.FunctionCall.ID, argsJSON))

				// ToolCallEnd signals the invocation description is complete,
				// not that the tool finished executing.
				e.emit(events.NewToolCallEndEvent(part.FunctionCall.ID))
				continue
			}

			// Function response: emit ToolCallResult with the serialized response.
			// Each result gets its own unique messageID (distinct from toolCallID).
			if part.FunctionResponse != nil {
				respJSON, err := marshalPooled(part.FunctionResponse.Response)
				if err != nil {
					return false, fmt.Errorf("failed to marshal function response: %w", err)
				}
				resultMsgID := events.GenerateMessageID()
				e.emit(events.NewToolCallResultEvent(resultMsgID, part.FunctionResponse.ID, respJSON))
				continue
			}
		}
	}

	// Emit state delta when the agent modifies session state.
	// ADK provides a flat map of changed keys; we convert each entry to a
	// JSON Patch "add" operation (RFC 6902). "add" is used instead of "replace"
	// because it works for both creating new keys and updating existing ones,
	// whereas "replace" fails if the path doesn't exist on the client.
	if len(ev.Actions.StateDelta) > 0 {
		ops := make([]events.JSONPatchOperation, 0, len(ev.Actions.StateDelta))
		for key, val := range ev.Actions.StateDelta {
			ops = append(ops, events.JSONPatchOperation{
				Op:    "add",
				Path:  "/" + escapeJSONPointer(key),
				Value: val,
			})
		}
		e.emit(events.NewStateDeltaEvent(ops))
	}

	// On turn completion, close all open lifecycle events.
	if ev.TurnComplete {
		closeTextMessage(e, state)
		closeReasoningMessage(e, state)

		if state.currentStepAuthor != "" {
			e.emit(events.NewStepFinishedEvent(state.currentStepAuthor))
			state.currentStepAuthor = ""
		}
	}

	return false, e.err
}

// closeTextMessage emits a TextMessageEndEvent for the currently open text message
// and records it as lastTextMessageID for use as parentMessageID on subsequent tool calls.
func closeTextMessage(e *emitter, state *streamState) {
	if state.currentTextMessageID == "" {
		return
	}
	e.emit(events.NewTextMessageEndEvent(state.currentTextMessageID))
	state.lastTextMessageID = state.currentTextMessageID
	state.currentTextMessageID = ""
}

// closeReasoningMessage emits ReasoningMessageEnd and ReasoningEnd events
// to close the currently open reasoning message and phase.
func closeReasoningMessage(e *emitter, state *streamState) {
	if state.currentReasoningMessageID != "" {
		e.emit(events.NewReasoningMessageEndEvent(state.currentReasoningMessageID))
		state.currentReasoningMessageID = ""
	}
	if state.currentReasoningPhaseID != "" {
		e.emit(events.NewReasoningEndEvent(state.currentReasoningPhaseID))
		state.currentReasoningPhaseID = ""
	}
}

// emitInterrupt converts an adk_request_confirmation FunctionCall into an
// AG-UI interrupt. It emits ToolCall events for the original tool (the agent's
// proposal — part of the AG-UI audit trail for tool-bound interrupts), then
// emits RunFinished with an interrupt outcome and sets state.runFinalized.
func (l *aguiLauncher) emitInterrupt(e *emitter, state *streamState, fc *genai.FunctionCall) error {
	originalCall, err := toolconfirmation.OriginalCallFrom(fc)
	if err != nil {
		return fmt.Errorf("failed to extract original call from confirmation: %w", err)
	}

	// Extract confirmation hint from the wrapper's args.
	var hintMessage string
	if tcRaw, ok := fc.Args["toolConfirmation"]; ok {
		switch v := tcRaw.(type) {
		case map[string]any:
			if h, ok := v["hint"].(string); ok {
				hintMessage = h
			}
		case *toolconfirmation.ToolConfirmation:
			hintMessage = v.Hint
		}
	}

	// Close all open lifecycle events before emitting the interrupt terminal
	// event. The AG-UI protocol requires all steps to be finished before
	// RunFinished is sent.
	closeTextMessage(e, state)
	closeReasoningMessage(e, state)
	if state.currentStepAuthor != "" {
		e.emit(events.NewStepFinishedEvent(state.currentStepAuthor))
		state.currentStepAuthor = ""
	}

	// Emit ToolCall events for the original tool (the agent's proposal).
	// Per the AG-UI spec ("Tool-bound interrupts"), the interrupted run
	// emits ToolCallStart/Args/End; the resumed run emits ToolCallResult.
	var startOpts []events.ToolCallStartOption
	if state.lastTextMessageID != "" {
		startOpts = append(startOpts, events.WithParentMessageID(state.lastTextMessageID))
	}
	e.emit(events.NewToolCallStartEvent(originalCall.ID, originalCall.Name, startOpts...))

	argsJSON, err := marshalPooled(originalCall.Args)
	if err != nil {
		return fmt.Errorf("failed to marshal original function call args: %w", err)
	}
	e.emit(events.NewToolCallArgsEvent(originalCall.ID, argsJSON))
	e.emit(events.NewToolCallEndEvent(originalCall.ID))

	// Build and emit RunFinished with interrupt outcome.
	e.emit(&runFinishedInterruptEvent{
		BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
		ThreadIDValue: state.threadID,
		RunIDValue:    state.runID,
		Outcome: &interruptOutcome{
			Type: "interrupt",
			Interrupts: []interrupt{{
				ID:         uuid.New().String(),
				Reason:     "tool_call",
				Message:    hintMessage,
				ToolCallID: originalCall.ID,
				ResponseSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"approved": map[string]any{"type": "boolean"},
					},
					"required": []string{"approved"},
				},
				Metadata: map[string]any{
					"adk": map[string]any{
						"confirmationCallId":   fc.ID,
						"confirmationCallName": toolconfirmation.FunctionCallName,
					},
				},
			}},
		},
	})
	state.runFinalized = true
	return nil
}

// escapeJSONPointer escapes a key for use in a JSON Pointer path (RFC 6901).
// The spec requires "~" → "~0" and "/" → "~1", in that order.
func escapeJSONPointer(key string) string {
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return key
}

// marshalPooled serializes v to JSON using a pooled buffer to reduce allocations
// on the event-emission hot path. Returns the JSON string without trailing newline.
func marshalPooled(v any) (string, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
