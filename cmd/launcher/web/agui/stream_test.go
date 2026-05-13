package agui
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/encoding/sse"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool/toolconfirmation"
	"google.golang.org/genai"
)

// sseEvent is a generic envelope for inspecting SSE event payloads.
// We unmarshal into map[string]any to avoid JSON tag collisions (e.g.
// "delta" is a string in TextMessageContent but an array in StateDelta).
type sseEvent struct {
	Type events.EventType
	Raw  map[string]any
}

func (e sseEvent) str(key string) string {
	v, _ := e.Raw[key].(string)
	return v
}

// parseSSEEvents extracts JSON data payloads from SSE-formatted output.
func parseSSEEvents(body string) []sseEvent {
	var out []sseEvent
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		after, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		after = strings.ReplaceAll(after, "\\n", "\n")
		after = strings.ReplaceAll(after, "\\r", "\r")

		var raw map[string]any
		if err := json.Unmarshal([]byte(after), &raw); err != nil {
			continue
		}
		typ, _ := raw["type"].(string)
		out = append(out, sseEvent{Type: events.EventType(typ), Raw: raw})
	}
	return out
}

// newTestEmitter creates an emitter backed by an httptest.Recorder so we can
// inspect the SSE output after processing.
func newTestEmitter() (*emitter, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	return newEmitter(context.Background(), rec, sse.NewSSEWriter(), nil, nil), rec
}

// newTestLauncher creates a minimal aguiLauncher for testing processEvent.
func newTestLauncher(appName string) *aguiLauncher {
	return &aguiLauncher{
		config: &AGUIConfig{appName: appName},
	}
}

func TestProcessEvent_TextStreaming(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	// Partial event should emit TextMessageStart + TextMessageContent.
	ev := session.NewEvent("inv1")
	ev.Content = genai.NewContentFromText("Hello", genai.RoleModel)
	ev.Partial = true

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 2 {
		t.Fatalf("got %d events, want 2", len(evts))
	}
	if evts[0].Type != events.EventTypeTextMessageStart {
		t.Errorf("event[0].Type = %v, want TEXT_MESSAGE_START", evts[0].Type)
	}
	if evts[1].Type != events.EventTypeTextMessageContent {
		t.Errorf("event[1].Type = %v, want TEXT_MESSAGE_CONTENT", evts[1].Type)
	}

	// Second partial should reuse the same messageID (no new Start).
	rec2 := httptest.NewRecorder()
	e2 := newEmitter(context.Background(), rec2, sse.NewSSEWriter(), nil, nil)

	ev2 := session.NewEvent("inv1")
	ev2.Content = genai.NewContentFromText(" world", genai.RoleModel)
	ev2.Partial = true

	if _, err := l.processEvent(e2, ev2, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts2 := parseSSEEvents(rec2.Body.String())
	if len(evts2) != 1 {
		t.Fatalf("got %d events, want 1 (content only)", len(evts2))
	}
	if evts2[0].Type != events.EventTypeTextMessageContent {
		t.Errorf("event[0].Type = %v, want TEXT_MESSAGE_CONTENT", evts2[0].Type)
	}
}

func TestProcessEvent_TextStreaming_FinalSkipped(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	// Non-partial (final) text event should be skipped.
	ev := session.NewEvent("inv1")
	ev.Content = genai.NewContentFromText("final", genai.RoleModel)
	ev.Partial = false

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 0 {
		t.Fatalf("got %d events, want 0 (final text skipped)", len(evts))
	}
}

func TestProcessEvent_ReasoningPhase(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role:  string(genai.RoleModel),
		Parts: []*genai.Part{{Text: "thinking...", Thought: true}},
	}
	ev.Partial = true

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 3 {
		t.Fatalf("got %d events, want 3 (ReasoningStart + MessageStart + MessageContent)", len(evts))
	}
	if evts[0].Type != events.EventTypeReasoningStart {
		t.Errorf("event[0].Type = %v, want REASONING_START", evts[0].Type)
	}
	if evts[1].Type != events.EventTypeReasoningMessageStart {
		t.Errorf("event[1].Type = %v, want REASONING_MESSAGE_START", evts[1].Type)
	}
	if evts[2].Type != events.EventTypeReasoningMessageContent {
		t.Errorf("event[2].Type = %v, want REASONING_MESSAGE_CONTENT", evts[2].Type)
	}
}

func TestProcessEvent_ReasoningToText_ClosesReasoning(t *testing.T) {
	l := newTestLauncher("test-app")
	state := &streamState{runID: "r1", threadID: "t1"}

	// First: open a reasoning phase.
	e1, _ := newTestEmitter()
	ev1 := session.NewEvent("inv1")
	ev1.Content = &genai.Content{
		Role:  string(genai.RoleModel),
		Parts: []*genai.Part{{Text: "thinking", Thought: true}},
	}
	ev1.Partial = true
	if _, err := l.processEvent(e1, ev1, state); err != nil {
		t.Fatalf("processEvent() reasoning error = %v", err)
	}
	if state.currentReasoningPhaseID == "" {
		t.Fatal("expected reasoning phase to be open")
	}

	// Second: text part should close reasoning first.
	e2, rec2 := newTestEmitter()
	ev2 := session.NewEvent("inv1")
	ev2.Content = genai.NewContentFromText("answer", genai.RoleModel)
	ev2.Partial = true
	if _, err := l.processEvent(e2, ev2, state); err != nil {
		t.Fatalf("processEvent() text error = %v", err)
	}

	evts := parseSSEEvents(rec2.Body.String())
	// Should see: ReasoningMessageEnd, ReasoningEnd, TextMessageStart, TextMessageContent
	types := make([]events.EventType, len(evts))
	for i, ev := range evts {
		types[i] = ev.Type
	}
	if len(types) != 4 {
		t.Fatalf("got %d events %v, want 4", len(types), types)
	}
	if types[0] != events.EventTypeReasoningMessageEnd {
		t.Errorf("event[0] = %v, want REASONING_MESSAGE_END", types[0])
	}
	if types[1] != events.EventTypeReasoningEnd {
		t.Errorf("event[1] = %v, want REASONING_END", types[1])
	}
	if types[2] != events.EventTypeTextMessageStart {
		t.Errorf("event[2] = %v, want TEXT_MESSAGE_START", types[2])
	}
}

func TestProcessEvent_FunctionCall(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role: string(genai.RoleModel),
		Parts: []*genai.Part{{
			FunctionCall: &genai.FunctionCall{
				ID:   "fc-1",
				Name: "get_weather",
				Args: map[string]any{"city": "London"},
			},
		}},
	}

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 3 {
		t.Fatalf("got %d events, want 3 (Start+Args+End)", len(evts))
	}
	if evts[0].Type != events.EventTypeToolCallStart {
		t.Errorf("event[0].Type = %v, want TOOL_CALL_START", evts[0].Type)
	}
	if evts[0].str("toolCallId") != "fc-1" {
		t.Errorf("event[0].toolCallId = %v, want fc-1", evts[0].str("toolCallId"))
	}
	if evts[0].str("toolCallName") != "get_weather" {
		t.Errorf("event[0].toolName = %v, want get_weather", evts[0].str("toolCallName"))
	}
	if evts[1].Type != events.EventTypeToolCallArgs {
		t.Errorf("event[1].Type = %v, want TOOL_CALL_ARGS", evts[1].Type)
	}
	if evts[2].Type != events.EventTypeToolCallEnd {
		t.Errorf("event[2].Type = %v, want TOOL_CALL_END", evts[2].Type)
	}
}

func TestProcessEvent_FunctionResponse(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role: string(genai.RoleModel),
		Parts: []*genai.Part{{
			FunctionResponse: &genai.FunctionResponse{
				ID:       "fc-1",
				Name:     "get_weather",
				Response: map[string]any{"temp": 20},
			},
		}},
	}

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1", len(evts))
	}
	if evts[0].Type != events.EventTypeToolCallResult {
		t.Errorf("event[0].Type = %v, want TOOL_CALL_RESULT", evts[0].Type)
	}
}

func TestProcessEvent_ConfirmationInterrupt_ClosesOpenStep(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{
		runID:             "r1",
		threadID:          "t1",
		currentStepAuthor: "sub-agent",
	}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role: string(genai.RoleModel),
		Parts: []*genai.Part{{
			FunctionCall: &genai.FunctionCall{
				ID:   "confirm-step",
				Name: toolconfirmation.FunctionCallName,
				Args: map[string]any{
					"toolConfirmation": map[string]any{
						"hint": "approve?",
					},
					"originalFunctionCall": map[string]any{
						"ID":   "orig-step",
						"Name": "do_thing",
					},
				},
			},
		}},
	}

	done, err := l.processEvent(e, ev, state)
	if err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}
	if !done {
		t.Fatal("processEvent() done = false, want true")
	}
	if state.currentStepAuthor != "" {
		t.Errorf("currentStepAuthor = %q, want empty (step should be closed)", state.currentStepAuthor)
	}

	evts := parseSSEEvents(rec.Body.String())
	// Should see: StepFinished, ToolCallStart, ToolCallArgs, ToolCallEnd, RunFinished
	if len(evts) < 2 {
		t.Fatalf("got %d events, want at least 2", len(evts))
	}
	if evts[0].Type != events.EventTypeStepFinished {
		t.Errorf("event[0].Type = %v, want STEP_FINISHED (close open step before interrupt)", evts[0].Type)
	}
	if evts[0].str("stepName") != "sub-agent" {
		t.Errorf("event[0].stepName = %v, want sub-agent", evts[0].str("stepName"))
	}
}

func TestProcessEvent_ConfirmationInterrupt(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role: string(genai.RoleModel),
		Parts: []*genai.Part{{
			FunctionCall: &genai.FunctionCall{
				ID:   "confirm-1",
				Name: toolconfirmation.FunctionCallName,
				Args: map[string]any{
					"toolConfirmation": map[string]any{
						"hint": "Approve sending email?",
					},
					"originalFunctionCall": map[string]any{
						"ID":   "orig-fc-1",
						"Name": "send_email",
						"Args": map[string]any{"to": "a@b.com"},
					},
				},
			},
		}},
	}

	done, err := l.processEvent(e, ev, state)

	if err != nil {
		t.Fatalf("processEvent() error = %v, want nil", err)
	}
	if !done {
		t.Fatal("processEvent() done = false, want true")
	}
	if !state.runFinalized {
		t.Error("state.runFinalized should be true after interrupt")
	}

	evts := parseSSEEvents(rec.Body.String())
	// Expect: ToolCallStart + ToolCallArgs + ToolCallEnd (original tool) + RunFinished (interrupt)
	if len(evts) != 4 {
		t.Fatalf("got %d events, want 4", len(evts))
	}

	// First three events should be for the ORIGINAL tool, not the wrapper.
	if evts[0].Type != events.EventTypeToolCallStart {
		t.Errorf("event[0].Type = %v, want TOOL_CALL_START", evts[0].Type)
	}
	if evts[0].str("toolCallId") != "orig-fc-1" {
		t.Errorf("event[0].toolCallId = %v, want orig-fc-1", evts[0].str("toolCallId"))
	}
	if evts[0].str("toolCallName") != "send_email" {
		t.Errorf("event[0].toolName = %v, want send_email", evts[0].str("toolCallName"))
	}
	if evts[1].Type != events.EventTypeToolCallArgs {
		t.Errorf("event[1].Type = %v, want TOOL_CALL_ARGS", evts[1].Type)
	}
	if evts[2].Type != events.EventTypeToolCallEnd {
		t.Errorf("event[2].Type = %v, want TOOL_CALL_END", evts[2].Type)
	}

	// Fourth event: RunFinished with interrupt outcome.
	if evts[3].Type != events.EventTypeRunFinished {
		t.Errorf("event[3].Type = %v, want RUN_FINISHED", evts[3].Type)
	}
	if evts[3].str("threadId") != "t1" {
		t.Errorf("event[3].threadId = %v, want t1", evts[3].str("threadId"))
	}
	if evts[3].str("runId") != "r1" {
		t.Errorf("event[3].runId = %v, want r1", evts[3].str("runId"))
	}
	outcomeRaw, ok := evts[3].Raw["outcome"]
	if !ok || outcomeRaw == nil {
		t.Fatal("event[3].outcome is missing, want interrupt outcome")
	}

	// Re-marshal and unmarshal the outcome to verify structure.
	outcomeBytes, err2 := json.Marshal(outcomeRaw)
	if err2 != nil {
		t.Fatalf("failed to marshal outcome: %v", err2)
	}
	var outcome interruptOutcome
	if err2 := json.Unmarshal(outcomeBytes, &outcome); err2 != nil {
		t.Fatalf("failed to unmarshal outcome: %v", err2)
	}
	if outcome.Type != "interrupt" {
		t.Errorf("outcome.Type = %v, want interrupt", outcome.Type)
	}
	if len(outcome.Interrupts) != 1 {
		t.Fatalf("len(outcome.Interrupts) = %d, want 1", len(outcome.Interrupts))
	}
	intr := outcome.Interrupts[0]
	if intr.Reason != "tool_call" {
		t.Errorf("interrupt.Reason = %v, want tool_call", intr.Reason)
	}
	if intr.ToolCallID != "orig-fc-1" {
		t.Errorf("interrupt.ToolCallID = %v, want orig-fc-1", intr.ToolCallID)
	}
	if intr.Message != "Approve sending email?" {
		t.Errorf("interrupt.Message = %v, want 'Approve sending email?'", intr.Message)
	}
	// Verify ADK metadata is stashed.
	adkMeta, ok := intr.Metadata["adk"].(map[string]any)
	if !ok {
		t.Fatal("interrupt.Metadata['adk'] missing or wrong type")
	}
	if adkMeta["confirmationCallId"] != "confirm-1" {
		t.Errorf("confirmationCallId = %v, want confirm-1", adkMeta["confirmationCallId"])
	}
}

func TestProcessEvent_ConfirmationInterrupt_TypedHint(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Content = &genai.Content{
		Role: string(genai.RoleModel),
		Parts: []*genai.Part{{
			FunctionCall: &genai.FunctionCall{
				ID:   "confirm-2",
				Name: toolconfirmation.FunctionCallName,
				Args: map[string]any{
					"toolConfirmation": &toolconfirmation.ToolConfirmation{
						Hint: "Delete all data?",
					},
					"originalFunctionCall": map[string]any{
						"ID":   "orig-fc-2",
						"Name": "delete_data",
					},
				},
			},
		}},
	}

	done, err := l.processEvent(e, ev, state)
	if err != nil {
		t.Fatalf("processEvent() error = %v, want nil", err)
	}
	if !done {
		t.Fatal("processEvent() done = false, want true")
	}

	evts := parseSSEEvents(rec.Body.String())
	// Parse the RunFinished outcome to check hint extraction.
	last := evts[len(evts)-1]
	outcomeBytes, _ := json.Marshal(last.Raw["outcome"])
	var outcome interruptOutcome
	if err := json.Unmarshal(outcomeBytes, &outcome); err != nil {
		t.Fatalf("failed to unmarshal outcome: %v", err)
	}
	if outcome.Interrupts[0].Message != "Delete all data?" {
		t.Errorf("interrupt.Message = %v, want 'Delete all data?'", outcome.Interrupts[0].Message)
	}
}

func TestProcessEvent_StateDelta(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	ev := session.NewEvent("inv1")
	ev.Actions.StateDelta["count"] = 42
	ev.Actions.StateDelta["nested/key"] = "value"

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1 (StateDelta)", len(evts))
	}
	if evts[0].Type != events.EventTypeStateDelta {
		t.Errorf("event[0].Type = %v, want STATE_DELTA", evts[0].Type)
	}
}

func TestProcessEvent_TurnComplete(t *testing.T) {
	l := newTestLauncher("test-app")
	state := &streamState{runID: "r1", threadID: "t1"}

	// Open a text message.
	e1, _ := newTestEmitter()
	ev1 := session.NewEvent("inv1")
	ev1.Content = genai.NewContentFromText("hi", genai.RoleModel)
	ev1.Partial = true
	_, _ = l.processEvent(e1, ev1, state)

	if state.currentTextMessageID == "" {
		t.Fatal("expected open text message")
	}

	// Also set a sub-agent step.
	state.currentStepAuthor = "sub-agent"

	// Turn complete should close everything.
	e2, rec2 := newTestEmitter()
	ev2 := session.NewEvent("inv1")
	ev2.TurnComplete = true
	if _, err := l.processEvent(e2, ev2, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec2.Body.String())
	types := make([]events.EventType, len(evts))
	for i, ev := range evts {
		types[i] = ev.Type
	}

	// Should see TextMessageEnd and StepFinished.
	hasTextEnd := false
	hasStepFinished := false
	for _, typ := range types {
		if typ == events.EventTypeTextMessageEnd {
			hasTextEnd = true
		}
		if typ == events.EventTypeStepFinished {
			hasStepFinished = true
		}
	}
	if !hasTextEnd {
		t.Error("expected TEXT_MESSAGE_END on turn complete")
	}
	if !hasStepFinished {
		t.Error("expected STEP_FINISHED on turn complete")
	}
	if state.currentTextMessageID != "" {
		t.Error("expected currentTextMessageID to be cleared")
	}
	if state.currentStepAuthor != "" {
		t.Error("expected currentStepAuthor to be cleared")
	}
}

func TestProcessEvent_StepEvents(t *testing.T) {
	l := newTestLauncher("test-app")
	e, rec := newTestEmitter()
	state := &streamState{runID: "r1", threadID: "t1"}

	// Sub-agent event should emit StepStarted.
	ev := session.NewEvent("inv1")
	ev.Author = "sub-agent-1"
	ev.Content = genai.NewContentFromText("sub response", genai.RoleModel)
	ev.Partial = true

	if _, err := l.processEvent(e, ev, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if evts[0].Type != events.EventTypeStepStarted {
		t.Errorf("event[0].Type = %v, want STEP_STARTED", evts[0].Type)
	}
	if evts[0].str("stepName") != "sub-agent-1" {
		t.Errorf("event[0].StepName = %v, want sub-agent-1", evts[0].str("stepName"))
	}

	// Root agent event should close the step without opening a new one.
	e2, rec2 := newTestEmitter()
	ev2 := session.NewEvent("inv1")
	ev2.Author = "test-app"
	ev2.Content = genai.NewContentFromText("root response", genai.RoleModel)
	ev2.Partial = true

	if _, err := l.processEvent(e2, ev2, state); err != nil {
		t.Fatalf("processEvent() error = %v", err)
	}

	evts2 := parseSSEEvents(rec2.Body.String())
	if evts2[0].Type != events.EventTypeStepFinished {
		t.Errorf("event[0].Type = %v, want STEP_FINISHED", evts2[0].Type)
	}
}

func TestProcessEvent_GenAIPartConverter(t *testing.T) {
	t.Run("converter handles part", func(t *testing.T) {
		l := newTestLauncher("test-app")
		l.config.genAIPartConverter = func(_ context.Context, _ *session.Event, _ *genai.Part) ([]events.Event, error) {
			return []events.Event{events.NewRunErrorEvent("custom")}, nil
		}
		e, rec := newTestEmitter()
		state := &streamState{runID: "r1", threadID: "t1"}

		ev := session.NewEvent("inv1")
		ev.Content = genai.NewContentFromText("text", genai.RoleModel)
		ev.Partial = true

		if _, err := l.processEvent(e, ev, state); err != nil {
			t.Fatalf("processEvent() error = %v", err)
		}

		evts := parseSSEEvents(rec.Body.String())
		if len(evts) != 1 {
			t.Fatalf("got %d events, want 1 (custom only)", len(evts))
		}
		if evts[0].Type != events.EventTypeRunError {
			t.Errorf("event[0].Type = %v, want RUN_ERROR (custom event)", evts[0].Type)
		}
	})

	t.Run("converter falls through", func(t *testing.T) {
		l := newTestLauncher("test-app")
		l.config.genAIPartConverter = func(_ context.Context, _ *session.Event, _ *genai.Part) ([]events.Event, error) {
			return nil, nil
		}
		e, rec := newTestEmitter()
		state := &streamState{runID: "r1", threadID: "t1"}

		ev := session.NewEvent("inv1")
		ev.Content = genai.NewContentFromText("text", genai.RoleModel)
		ev.Partial = true

		if _, err := l.processEvent(e, ev, state); err != nil {
			t.Fatalf("processEvent() error = %v", err)
		}

		evts := parseSSEEvents(rec.Body.String())
		if len(evts) < 1 {
			t.Fatal("expected default text events after converter fallthrough")
		}
		if evts[0].Type != events.EventTypeTextMessageStart {
			t.Errorf("event[0].Type = %v, want TEXT_MESSAGE_START", evts[0].Type)
		}
	})
}

func TestRunFinishedInterruptEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   runFinishedInterruptEvent
		wantErr bool
	}{
		{
			name: "valid",
			event: runFinishedInterruptEvent{
				BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
				ThreadIDValue: "t1",
				RunIDValue:    "r1",
				Outcome: &interruptOutcome{
					Type:       "interrupt",
					Interrupts: []interrupt{{ID: "i1", Reason: "tool_call"}},
				},
			},
			wantErr: false,
		},
		{
			name: "missing threadId",
			event: runFinishedInterruptEvent{
				BaseEvent:  events.NewBaseEvent(events.EventTypeRunFinished),
				RunIDValue: "r1",
				Outcome: &interruptOutcome{
					Type:       "interrupt",
					Interrupts: []interrupt{{ID: "i1", Reason: "tool_call"}},
				},
			},
			wantErr: true,
		},
		{
			name: "missing runId",
			event: runFinishedInterruptEvent{
				BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
				ThreadIDValue: "t1",
				Outcome: &interruptOutcome{
					Type:       "interrupt",
					Interrupts: []interrupt{{ID: "i1", Reason: "tool_call"}},
				},
			},
			wantErr: true,
		},
		{
			name: "nil outcome",
			event: runFinishedInterruptEvent{
				BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
				ThreadIDValue: "t1",
				RunIDValue:    "r1",
			},
			wantErr: true,
		},
		{
			name: "empty interrupts",
			event: runFinishedInterruptEvent{
				BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
				ThreadIDValue: "t1",
				RunIDValue:    "r1",
				Outcome:       &interruptOutcome{Type: "interrupt"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunFinishedInterruptEvent_ToJSON(t *testing.T) {
	ev := &runFinishedInterruptEvent{
		BaseEvent:     events.NewBaseEvent(events.EventTypeRunFinished),
		ThreadIDValue: "t1",
		RunIDValue:    "r1",
		Outcome: &interruptOutcome{
			Type: "interrupt",
			Interrupts: []interrupt{{
				ID:         "i1",
				Reason:     "tool_call",
				Message:    "approve?",
				ToolCallID: "tc-1",
			}},
		},
	}

	data, err := ev.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if raw["type"] != string(events.EventTypeRunFinished) {
		t.Errorf("type = %v, want RUN_FINISHED", raw["type"])
	}
	if raw["threadId"] != "t1" {
		t.Errorf("threadId = %v, want t1", raw["threadId"])
	}
	if raw["runId"] != "r1" {
		t.Errorf("runId = %v, want r1", raw["runId"])
	}
	outcome, ok := raw["outcome"].(map[string]any)
	if !ok {
		t.Fatal("outcome field missing or wrong type")
	}
	if outcome["type"] != "interrupt" {
		t.Errorf("outcome.type = %v, want interrupt", outcome["type"])
	}
}

func TestEscapeJSONPointer(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"simple", "simple"},
		{"a/b", "a~1b"},
		{"a~b", "a~0b"},
		{"a~/b", "a~0~1b"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := escapeJSONPointer(tt.input); got != tt.want {
				t.Errorf("escapeJSONPointer(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

type onEmitFunc struct {
	PassthroughInterceptor
	fn func(ctx context.Context, callCtx *CallContext, event events.Event) (events.Event, error)
}

func (o *onEmitFunc) OnEmit(ctx context.Context, callCtx *CallContext, event events.Event) (events.Event, error) {
	return o.fn(ctx, callCtx, event)
}

func TestEmitter_OnEmit_PassThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
		return event, nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{interceptor}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))
	if e.err != nil {
		t.Fatalf("emit error = %v", e.err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1", len(evts))
	}
	if evts[0].Type != events.EventTypeRunStarted {
		t.Errorf("event type = %v, want RUN_STARTED", evts[0].Type)
	}
}

func TestEmitter_OnEmit_Suppress(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, _ events.Event) (events.Event, error) {
		return nil, nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{interceptor}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))
	if e.err != nil {
		t.Fatalf("emit error = %v", e.err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 0 {
		t.Fatalf("got %d events, want 0 (suppressed)", len(evts))
	}
}

func TestEmitter_OnEmit_Error(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, _ events.Event) (events.Event, error) {
		return nil, fmt.Errorf("interceptor abort")
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{interceptor}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))
	if e.err == nil {
		t.Fatal("expected error from interceptor")
	}
	if e.err.Error() != "interceptor abort" {
		t.Errorf("error = %v, want 'interceptor abort'", e.err)
	}

	// Subsequent emits should be no-ops.
	e.emit(events.NewRunFinishedEvent("t1", "r1"))
	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 0 {
		t.Fatalf("got %d events after error, want 0", len(evts))
	}
}

func TestEmitter_OnEmit_Transform(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
		// Replace any event with RunError.
		return events.NewRunErrorEvent("transformed"), nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{interceptor}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))
	if e.err != nil {
		t.Fatalf("emit error = %v", e.err)
	}

	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1", len(evts))
	}
	if evts[0].Type != events.EventTypeRunError {
		t.Errorf("event type = %v, want RUN_ERROR (transformed)", evts[0].Type)
	}
}

func TestEmitter_OnEmit_Chain(t *testing.T) {
	rec := httptest.NewRecorder()
	var order []string

	first := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
		order = append(order, "first")
		return event, nil
	}}
	second := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
		order = append(order, "second")
		return event, nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{first, second}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))
	if e.err != nil {
		t.Fatalf("emit error = %v", e.err)
	}

	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("chain order = %v, want [first second]", order)
	}
}

func TestEmitter_OnEmit_ChainSuppressShortCircuits(t *testing.T) {
	rec := httptest.NewRecorder()
	var secondCalled bool

	first := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, _ events.Event) (events.Event, error) {
		return nil, nil
	}}
	second := &onEmitFunc{fn: func(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
		secondCalled = true
		return event, nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{first, second}, &CallContext{})

	e.emit(events.NewRunStartedEvent("t1", "r1"))

	if secondCalled {
		t.Error("second interceptor should not be called after first suppresses")
	}
	evts := parseSSEEvents(rec.Body.String())
	if len(evts) != 0 {
		t.Fatalf("got %d events, want 0 (suppressed by first)", len(evts))
	}
}

func TestEmitter_OnEmit_ReceivesCallContext(t *testing.T) {
	rec := httptest.NewRecorder()
	callCtx := &CallContext{User: &User{Name: "test-user", Authenticated: true}}

	var receivedCtx *CallContext
	interceptor := &onEmitFunc{fn: func(_ context.Context, cc *CallContext, event events.Event) (events.Event, error) {
		receivedCtx = cc
		return event, nil
	}}
	e := newEmitter(context.Background(), rec, sse.NewSSEWriter(), []CallInterceptor{interceptor}, callCtx)

	e.emit(events.NewRunStartedEvent("t1", "r1"))

	if receivedCtx == nil {
		t.Fatal("OnEmit did not receive CallContext")
	}
	if receivedCtx.User.Name != "test-user" {
		t.Errorf("CallContext.User.Name = %v, want test-user", receivedCtx.User.Name)
	}
}

func TestPassthroughInterceptor(t *testing.T) {
	var p PassthroughInterceptor
	ctx := context.Background()

	newCtx, err := p.Before(ctx, nil, nil, nil)
	if err != nil {
		t.Errorf("Before() error = %v", err)
	}
	if newCtx != ctx {
		t.Error("Before() should return the same context")
	}

	event := events.NewRunStartedEvent("t1", "r1")
	gotEvent, err := p.OnEmit(ctx, nil, event)
	if err != nil {
		t.Errorf("OnEmit() error = %v", err)
	}
	if gotEvent != event {
		t.Error("OnEmit() should return the same event")
	}

	if err := p.After(ctx, nil, nil); err != nil {
		t.Errorf("After() error = %v", err)
	}
}

func TestMarshalPooled(t *testing.T) {
	got, err := marshalPooled(map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("marshalPooled() error = %v", err)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("marshalPooled() should not have trailing newline")
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if decoded["key"] != "value" {
		t.Errorf("decoded[key] = %v, want value", decoded["key"])
	}
}
