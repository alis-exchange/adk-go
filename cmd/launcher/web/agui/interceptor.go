package agui

import (
	"context"
	"net/http"

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

// CallInterceptor allows consumers to observe, modify, or reject an AG-UI request.
// Before is invoked before the agent run begins; After is invoked when the handler
// exits, regardless of success or failure. Interceptors execute in registration order
// for Before and reverse order for After.
type CallInterceptor interface {
	// Before is called before the agent run begins.
	// Return a new context to pass information down the call stack.
	// Return an error to reject the request before SSE streaming starts.
	Before(ctx context.Context, callCtx *CallContext, req *types.RunAgentInput, httpRequest *http.Request) (context.Context, error)

	// After is called when the handler exits. The err parameter carries the
	// handler-level error (nil on success). After interceptors run in reverse
	// registration order and only for interceptors whose Before succeeded.
	After(ctx context.Context, callCtx *CallContext, err error) error
}
