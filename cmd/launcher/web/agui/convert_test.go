package agui

import (
	"context"
	"iter"
	"slices"
	"testing"
	"time"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/types"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

var (
	_ session.Session = (*testSession)(nil)
	_ session.Events  = (*testEvents)(nil)
	_ session.State   = (*testState)(nil)
)

func TestConvertSessionToMessages_TextMessage(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = genai.NewContentFromText("Hello, world!", genai.RoleModel)
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Role != types.RoleAssistant {
		t.Errorf("role = %v, want assistant", msgs[0].Role)
	}
	content, ok := msgs[0].Content.(string)
	if !ok || content != "Hello, world!" {
		t.Errorf("content = %v, want 'Hello, world!'", msgs[0].Content)
	}
}

func TestConvertSessionToMessages_UserMessage(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = genai.NewContentFromText("Hi there", genai.RoleUser)
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Role != types.RoleUser {
		t.Errorf("role = %v, want user", msgs[0].Role)
	}
}

func TestConvertSessionToMessages_FunctionCall(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{{
				FunctionCall: &genai.FunctionCall{
					ID:   "call-1",
					Name: "get_weather",
					Args: map[string]any{"location": "NYC"},
				},
			}},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Role != types.RoleAssistant {
		t.Errorf("role = %v, want assistant", msgs[0].Role)
	}
	if len(msgs[0].ToolCalls) != 1 {
		t.Fatalf("got %d tool calls, want 1", len(msgs[0].ToolCalls))
	}
	tc := msgs[0].ToolCalls[0]
	if tc.ID != "call-1" {
		t.Errorf("toolCall.ID = %v, want call-1", tc.ID)
	}
	if tc.Function.Name != "get_weather" {
		t.Errorf("toolCall.Function.Name = %v, want get_weather", tc.Function.Name)
	}
	if tc.Type != types.ToolCallTypeFunction {
		t.Errorf("toolCall.Type = %v, want function", tc.Type)
	}
}

func TestConvertSessionToMessages_FunctionResponse(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{{
				FunctionResponse: &genai.FunctionResponse{
					ID:       "call-1",
					Name:     "get_weather",
					Response: map[string]any{"temp": 22},
				},
			}},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Role != types.RoleTool {
		t.Errorf("role = %v, want tool", msgs[0].Role)
	}
	if msgs[0].ToolCallID != "call-1" {
		t.Errorf("toolCallId = %v, want call-1", msgs[0].ToolCallID)
	}
}

func TestConvertSessionToMessages_Thought(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{
				{Text: "thinking about it...", Thought: true},
				{Text: "Here is my answer"},
			},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}

	// Text message comes first (accumulated before thought is flushed).
	assistantMsg := msgs[0]
	if assistantMsg.Role != types.RoleAssistant {
		t.Errorf("msgs[0].role = %v, want assistant", assistantMsg.Role)
	}
	content, _ := assistantMsg.Content.(string)
	if content != "Here is my answer" {
		t.Errorf("msgs[0].content = %v, want 'Here is my answer'", content)
	}

	reasoningMsg := msgs[1]
	if reasoningMsg.Role != types.RoleReasoning {
		t.Errorf("msgs[1].role = %v, want reasoning", reasoningMsg.Role)
	}
	reasoningContent, _ := reasoningMsg.Content.(string)
	if reasoningContent != "thinking about it..." {
		t.Errorf("msgs[1].content = %v, want 'thinking about it...'", reasoningContent)
	}
}

func TestConvertSessionToMessages_SkipsPartialEvents(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		partial := session.NewEvent("inv1")
		partial.Content = genai.NewContentFromText("partial delta", genai.RoleModel)
		partial.Partial = true
		s.events = append(s.events, partial)

		final := session.NewEvent("inv1")
		final.Content = genai.NewContentFromText("full text", genai.RoleModel)
		s.events = append(s.events, final)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	content, _ := msgs[0].Content.(string)
	if content != "full text" {
		t.Errorf("content = %v, want 'full text'", content)
	}
}

func TestConvertSessionToMessages_WithAfter(t *testing.T) {
	now := time.Now()
	sess := buildSession(func(s *testSession) {
		old := session.NewEvent("inv1")
		old.Content = genai.NewContentFromText("old message", genai.RoleModel)
		old.Timestamp = now.Add(-10 * time.Minute)
		s.events = append(s.events, old)

		recent := session.NewEvent("inv2")
		recent.Content = genai.NewContentFromText("recent message", genai.RoleModel)
		recent.Timestamp = now.Add(-1 * time.Minute)
		s.events = append(s.events, recent)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess,
		WithConvertAfter(now.Add(-5*time.Minute)),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	content, _ := msgs[0].Content.(string)
	if content != "recent message" {
		t.Errorf("content = %v, want 'recent message'", content)
	}
}

func TestConvertSessionToMessages_WithLimit(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		for i := 0; i < 5; i++ {
			ev := session.NewEvent("inv1")
			ev.Content = genai.NewContentFromText("msg", genai.RoleModel)
			s.events = append(s.events, ev)
		}
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess,
		WithConvertLimit(2),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
}

func TestConvertSessionToMessages_WithPartConverter(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{{
				FunctionCall: &genai.FunctionCall{
					ID:   "call-1",
					Name: "internal_tool",
					Args: map[string]any{},
				},
			}, {
				FunctionResponse: &genai.FunctionResponse{
					ID:       "call-1",
					Name:     "internal_tool",
					Response: map[string]any{"surface": "dashboard"},
				},
			}},
		}
		s.events = append(s.events, ev)
	})

	converter := func(_ context.Context, _ *session.Event, part *genai.Part) ([]events.Event, error) {
		// Suppress the function call.
		if part.FunctionCall != nil && part.FunctionCall.Name == "internal_tool" {
			return []events.Event{}, nil
		}
		// Convert response to activity.
		if part.FunctionResponse != nil && part.FunctionResponse.Name == "internal_tool" {
			return []events.Event{
				events.NewActivitySnapshotEvent("surface-1", "custom-ui", part.FunctionResponse.Response),
			}, nil
		}
		return nil, nil
	}

	msgs, err := ConvertSessionToMessages(context.Background(), sess,
		WithPartConverter(converter),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Role != types.RoleActivity {
		t.Errorf("role = %v, want activity", msgs[0].Role)
	}
	if msgs[0].ActivityType != "custom-ui" {
		t.Errorf("activityType = %v, want custom-ui", msgs[0].ActivityType)
	}
}

func TestConvertSessionToMessages_MultipleToolCalls(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{
				{FunctionCall: &genai.FunctionCall{ID: "c1", Name: "tool_a", Args: map[string]any{"x": 1}}},
				{FunctionCall: &genai.FunctionCall{ID: "c2", Name: "tool_b", Args: map[string]any{"y": 2}}},
			},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if len(msgs[0].ToolCalls) != 2 {
		t.Fatalf("got %d tool calls, want 2", len(msgs[0].ToolCalls))
	}
}

func TestConvertSessionToMessages_EmptySession(t *testing.T) {
	sess := buildSession(func(_ *testSession) {})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("got %d messages, want 0", len(msgs))
	}
}

func TestConvertSessionToMessages_MessageIDs(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.ID = "evt-abc"
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{
				{FunctionResponse: &genai.FunctionResponse{ID: "c1", Name: "t", Response: map[string]any{}}},
				{FunctionResponse: &genai.FunctionResponse{ID: "c2", Name: "t", Response: map[string]any{}}},
			},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].ID != "evt-abc" {
		t.Errorf("msgs[0].ID = %v, want evt-abc", msgs[0].ID)
	}
	if msgs[1].ID != "evt-abc-1" {
		t.Errorf("msgs[1].ID = %v, want evt-abc-1", msgs[1].ID)
	}
}

func TestConvertSessionToMessages_TextBeforeFunctionCall(t *testing.T) {
	sess := buildSession(func(s *testSession) {
		ev := session.NewEvent("inv1")
		ev.ID = "evt-1"
		ev.Content = &genai.Content{
			Role: string(genai.RoleModel),
			Parts: []*genai.Part{
				{Text: "Let me check."},
				{FunctionCall: &genai.FunctionCall{ID: "c1", Name: "search", Args: map[string]any{}}},
			},
		}
		s.events = append(s.events, ev)
	})

	msgs, err := ConvertSessionToMessages(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	// Text is flushed before the tool call message.
	content, _ := msgs[0].Content.(string)
	if content != "Let me check." {
		t.Errorf("msgs[0].content = %v, want 'Let me check.'", content)
	}
	if len(msgs[1].ToolCalls) != 1 {
		t.Errorf("msgs[1] should have 1 tool call, got %d", len(msgs[1].ToolCalls))
	}
}

// --- test helpers ---

type testSession struct {
	id     string
	events []*session.Event
}

func (s *testSession) ID() string                      { return s.id }
func (s *testSession) AppName() string                  { return "test-app" }
func (s *testSession) UserID() string                   { return "test-user" }
func (s *testSession) State() session.State             { return &testState{} }
func (s *testSession) Events() session.Events           { return &testEvents{events: s.events} }
func (s *testSession) LastUpdateTime() time.Time        { return time.Now() }

type testEvents struct {
	events []*session.Event
}

func (e *testEvents) All() iter.Seq[*session.Event] {
	return slices.Values(e.events)
}

func (e *testEvents) Len() int              { return len(e.events) }
func (e *testEvents) At(i int) *session.Event { return e.events[i] }

type testState struct{}

func (s *testState) Get(_ string) (any, error) { return nil, session.ErrStateKeyNotExist }
func (s *testState) Set(_ string, _ any) error { return nil }
func (s *testState) All() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {}
}

func buildSession(setup func(*testSession)) session.Session {
	s := &testSession{id: "test-session"}
	setup(s)
	return s
}
