package agui

import (
	"context"
	"net/http"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/types"
)

// User represents the authenticated user making the AG-UI request.
type User struct {
	Name          string
	Authenticated bool
}

// CallContext holds metadata about the current AG-UI request.
type CallContext struct {
	User *User
}

// CallInterceptor allows consumers to observe, modify, or reject an AG-UI request
// and to intercept individual SSE events before they are written to the wire.
// Before is invoked before the agent run begins; OnEmit is invoked for each AG-UI
// event; After is invoked when the handler exits, regardless of success or failure.
// Interceptors execute in registration order for Before and OnEmit, and reverse
// order for After.
type CallInterceptor interface {
	// Before is called before the agent run begins.
	// Return a new context to pass information down the call stack.
	// Return an error to reject the request before SSE streaming starts.
	Before(ctx context.Context, callCtx *CallContext, req *types.RunAgentInput, httpRequest *http.Request) (context.Context, error)

	// OnEmit is called for each AG-UI event before it is written to the SSE stream.
	// Return the event (possibly modified) to emit it, or nil to suppress it.
	// Return an error to abort the stream. When multiple interceptors are
	// registered, they chain in registration order: each receives the event
	// returned by the previous interceptor.
	OnEmit(ctx context.Context, callCtx *CallContext, event events.Event) (events.Event, error)

	// After is called when the handler exits. The err parameter carries the
	// handler-level error (nil on success). After interceptors run in reverse
	// registration order and only for interceptors whose Before succeeded.
	After(ctx context.Context, callCtx *CallContext, err error) error
}

// PassthroughInterceptor provides no-op implementations of all CallInterceptor
// methods. Embed it in your interceptor struct to only override the methods you
// need, avoiding boilerplate stubs for unused hooks.
type PassthroughInterceptor struct{}

// Before returns the context unchanged.
func (PassthroughInterceptor) Before(ctx context.Context, _ *CallContext, _ *types.RunAgentInput, _ *http.Request) (context.Context, error) {
	return ctx, nil
}

// OnEmit returns the event unchanged.
func (PassthroughInterceptor) OnEmit(_ context.Context, _ *CallContext, event events.Event) (events.Event, error) {
	return event, nil
}

// After returns nil.
func (PassthroughInterceptor) After(_ context.Context, _ *CallContext, _ error) error {
	return nil
}
