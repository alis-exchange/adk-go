package agui

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/types"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

type convertConfig struct {
	partConverter GenAIPartConverter
	after         time.Time
	limit         int
}

// ConvertOption configures [ConvertSessionToMessages].
type ConvertOption func(*convertConfig)

// WithPartConverter registers the same [GenAIPartConverter] used for live SSE
// streaming. When converting session history, the converter is called for each
// [genai.Part]. If it returns events (non-nil), those events are folded into
// [types.Message] objects:
//
//   - [events.ActivitySnapshotEvent] → Message{role: "activity", …}
//   - Empty slice → part is suppressed (same as live SSE)
//   - nil return → fall through to default conversion
//
// This allows a single converter (e.g. an A2UI part converter) to work
// unchanged for both live streaming and history retrieval.
func WithPartConverter(fn GenAIPartConverter) ConvertOption {
	return func(c *convertConfig) { c.partConverter = fn }
}

// WithConvertAfter filters events to only those with timestamps at or after t.
// Used for cursor-based pagination.
func WithConvertAfter(t time.Time) ConvertOption {
	return func(c *convertConfig) { c.after = t }
}

// WithConvertLimit caps the number of session events to process.
// A value of 0 means no limit.
func WithConvertLimit(n int) ConvertOption {
	return func(c *convertConfig) { c.limit = n }
}

// ConvertSessionToMessages converts ADK session events into AG-UI [types.Message]
// objects suitable for a MESSAGES_SNAPSHOT event or direct JSON serialization.
//
// It processes complete (non-streaming) events from the session's event history:
// text parts become assistant messages, function calls become assistant messages
// with tool calls, function responses become tool messages, and thought parts
// become reasoning messages.
//
// Partial (streaming-intermediate) events are skipped because they contain
// incremental deltas that are superseded by the final non-partial event.
func ConvertSessionToMessages(ctx context.Context, sess session.Session, opts ...ConvertOption) ([]types.Message, error) {
	cfg := &convertConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var messages []types.Message
	processed := 0

	for ev := range sess.Events().All() {
		if ev == nil || ev.Content == nil {
			continue
		}
		if !cfg.after.IsZero() && ev.Timestamp.Before(cfg.after) {
			continue
		}
		if cfg.limit > 0 && processed >= cfg.limit {
			break
		}
		processed++

		// During live streaming ADK emits partial events with incremental text
		// deltas, followed by a final non-partial event with the full content.
		// Only the final event is meaningful for history.
		if ev.Partial {
			continue
		}

		msgs, err := convertEvent(ctx, ev, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to convert event %s: %w", ev.ID, err)
		}
		messages = append(messages, msgs...)
	}

	return messages, nil
}

// convertEvent converts a single ADK session event into zero or more AG-UI messages.
func convertEvent(ctx context.Context, ev *session.Event, cfg *convertConfig) ([]types.Message, error) {
	role := mapContentRole(ev.Content.Role)

	// A single ADK event can contain multiple genai.Parts (e.g. text followed
	// by a function call, or parallel function calls). Buffers merge consecutive
	// parts of the same kind into one AG-UI message instead of one-per-part:
	//   textBuf    – non-thought text → single assistant message
	//   thoughtBuf – reasoning/thought text → single reasoning message
	//   toolCalls  – function calls → one assistant message with ToolCall[]
	var messages []types.Message
	var textBuf string
	var toolCalls []types.ToolCall
	var thoughtBuf string
	// partIndex counts messages produced so far from this event, used to
	// generate stable IDs: first message reuses the event ID, subsequent
	// ones get "{eventID}-{partIndex}" suffixes.
	partIndex := 0

	for _, part := range ev.Content.Parts {
		if part == nil {
			continue
		}

		if cfg.partConverter != nil {
			converted, err := cfg.partConverter(ctx, ev, part)
			if err != nil {
				return nil, err
			}
			if converted != nil {
				msgs := foldEventsToMessages(ev.ID, partIndex, converted)
				messages = append(messages, msgs...)
				partIndex += len(msgs)
				continue
			}
		}

		if part.Thought && part.Text != "" {
			thoughtBuf += part.Text
			continue
		}

		if part.Text != "" && !part.Thought {
			textBuf += part.Text
			continue
		}

		if part.FunctionCall != nil {
			// Flush accumulated text before tool calls so it appears as a
			// separate preceding message (e.g. "Let me check." before the
			// tool invocation), matching how the live SSE stream orders them.
			if textBuf != "" {
				messages = append(messages, types.Message{
					ID:      messageID(ev.ID, partIndex),
					Role:    role,
					Content: textBuf,
				})
				partIndex++
				textBuf = ""
			}

			argsJSON, err := marshalMap(part.FunctionCall.Args)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal function call args: %w", err)
			}
			toolCalls = append(toolCalls, types.ToolCall{
				ID:   part.FunctionCall.ID,
				Type: types.ToolCallTypeFunction,
				Function: types.FunctionCall{
					Name:      part.FunctionCall.Name,
					Arguments: argsJSON,
				},
			})
			continue
		}

		if part.FunctionResponse != nil {
			respJSON, err := marshalMap(part.FunctionResponse.Response)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal function response: %w", err)
			}
			messages = append(messages, types.Message{
				ID:         messageID(ev.ID, partIndex),
				Role:       types.RoleTool,
				Content:    respJSON,
				ToolCallID: part.FunctionResponse.ID,
			})
			partIndex++
			continue
		}
	}

	// Flush any remaining accumulated state into messages.
	// Order: tool calls, then text, then thoughts — thoughts are emitted last
	// because they represent internal reasoning that logically precedes the
	// visible response but is rendered separately in the UI.
	if len(toolCalls) > 0 {
		messages = append(messages, types.Message{
			ID:        messageID(ev.ID, partIndex),
			Role:      role,
			ToolCalls: toolCalls,
		})
		partIndex++
	}

	if textBuf != "" {
		messages = append(messages, types.Message{
			ID:      messageID(ev.ID, partIndex),
			Role:    role,
			Content: textBuf,
		})
		partIndex++
	}

	if thoughtBuf != "" {
		messages = append(messages, types.Message{
			ID:      messageID(ev.ID, partIndex),
			Role:    types.RoleReasoning,
			Content: thoughtBuf,
		})
		partIndex++
	}

	return messages, nil
}

// foldEventsToMessages converts AG-UI streaming events (returned by a
// [GenAIPartConverter]) into finalized [types.Message] objects. This bridges
// the two AG-UI delivery modes: converters are written for the live SSE path
// and return streaming events, but history needs complete messages. Only event
// types that carry displayable content are folded; lifecycle events (Start/End)
// are ignored since they have no meaning in a static message list.
func foldEventsToMessages(eventID string, startIndex int, evts []events.Event) []types.Message {
	var messages []types.Message
	idx := startIndex

	for _, evt := range evts {
		switch e := evt.(type) {
		case *events.ActivitySnapshotEvent:
			messages = append(messages, types.Message{
				ID:           messageID(eventID, idx),
				Role:         types.RoleActivity,
				ActivityType: e.ActivityType,
				Content:      e.Content,
			})
			idx++

		case *events.TextMessageContentEvent:
			messages = append(messages, types.Message{
				ID:      messageID(eventID, idx),
				Role:    types.RoleAssistant,
				Content: e.Delta,
			})
			idx++
		}
	}

	return messages
}

// mapContentRole translates a genai content role to the AG-UI message role.
// ADK uses "model" for agent-generated content; AG-UI uses "assistant".
func mapContentRole(genaiRole string) types.Role {
	switch genai.Role(genaiRole) {
	case genai.RoleUser:
		return types.RoleUser
	default:
		return types.RoleAssistant
	}
}

// messageID produces a stable, unique ID for each message derived from a
// single ADK event. The first message (partIndex 0) reuses the event ID
// directly; subsequent messages append a numeric suffix. This ensures the
// same session always produces the same message IDs across calls.
func messageID(eventID string, partIndex int) string {
	if partIndex == 0 {
		return eventID
	}
	return fmt.Sprintf("%s-%d", eventID, partIndex)
}

func marshalMap(m map[string]any) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal map: %w", err)
	}
	return string(b), nil
}
