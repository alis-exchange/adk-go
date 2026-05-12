// Package agui implements an AG-UI protocol sublauncher for ADK agents.
// It bridges ADK agent execution to the AG-UI SSE protocol, enabling
// CopilotKit and other AG-UI-compatible frontends to stream agent responses.
package agui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/types"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/encoding/sse"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/cmd/launcher"
	weblauncher "google.golang.org/adk/cmd/launcher/web"
	"google.golang.org/adk/internal/cli/util"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

var _ weblauncher.Sublauncher = &aguiLauncher{}

// CORSConfig controls Cross-Origin Resource Sharing headers on the AG-UI endpoint.
// Browser-based frontends (CopilotKit, custom Vue/React apps) require CORS
// because the frontend origin differs from the agent server origin.
type CORSConfig struct {
	// AllowedOrigins is the list of origins permitted to access the endpoint.
	// Use ["*"] to allow all origins (development only — not recommended for production).
	AllowedOrigins []string

	// AllowedHeaders lists HTTP headers the client may send.
	// Defaults to ["Content-Type", "Authorization"] if empty.
	AllowedHeaders []string

	// ExposeHeaders lists response headers the browser may read.
	// Defaults to none if empty.
	ExposeHeaders []string

	// AllowCredentials indicates whether the response to the request can include credentials.
	AllowCredentials bool
}

// GenAIPartConverter converts a genai.Part from an ADK session event into
// zero or more AG-UI events, allowing consumers to intercept, transform, or
// suppress specific parts before the default event mapping runs.
//
// Return a non-nil slice (including empty) to indicate the part was handled;
// the default processing is skipped and the returned events are emitted.
// Return (nil, nil) to fall through to the default handler for that part.
//
// This mirrors the adka2a.GenAIPartConverter pattern: nil returns mean
// "not handled, use default", while non-nil returns (even an empty slice)
// mean "handled, skip default".
type GenAIPartConverter func(ctx context.Context, adkEvent *session.Event, part *genai.Part) ([]events.Event, error)

// AGUIConfig holds configuration for the AG-UI sublauncher.
type AGUIConfig struct {
	appName           string
	pathPrefix        string
	interceptors      []CallInterceptor
	cors              *CORSConfig
	capabilities      *Capabilities
	genAIPartConverter GenAIPartConverter
}

// Option configures an AGUIConfig.
type Option func(*AGUIConfig)

// WithInterceptor adds a CallInterceptor to the AG-UI launcher.
// Interceptors are executed in the order they are added.
func WithInterceptor(interceptor CallInterceptor) Option {
	return func(c *AGUIConfig) {
		c.interceptors = append(c.interceptors, interceptor)
	}
}

// WithCORS enables CORS headers on the AG-UI endpoint. This is required when
// browser-based frontends (CopilotKit, custom SPAs) call the endpoint from a
// different origin than the agent server. The middleware handles OPTIONS
// preflight requests and sets Access-Control-* headers on all responses.
func WithCORS(cors CORSConfig) Option {
	return func(c *AGUIConfig) {
		c.cors = &cors
	}
}

// WithCapabilities declares the agent's capabilities so clients can discover
// supported features via GET /capabilities and adapt their UI accordingly.
func WithCapabilities(caps Capabilities) Option {
	return func(c *AGUIConfig) {
		c.capabilities = &caps
	}
}

// WithGenAIPartConverter registers a callback that intercepts genai.Part values
// from ADK session events before the default AG-UI event mapping runs.
//
// When the converter returns a non-nil slice, those events are emitted and the
// default handling for that part is skipped. When it returns (nil, nil), the
// default mapping (text streaming, tool calls, etc.) proceeds normally.
//
// This is the AG-UI equivalent of [adka2a.ExecutorConfig.GenAIPartConverter]:
// it lets consumers customize how specific parts (e.g. generative UI payloads,
// extension-specific function calls) are represented on the SSE stream without
// modifying the launcher itself.
func WithGenAIPartConverter(converter GenAIPartConverter) Option {
	return func(c *AGUIConfig) {
		c.genAIPartConverter = converter
	}
}

// aguiLauncher implements weblauncher.Sublauncher for the AG-UI protocol.
type aguiLauncher struct {
	flags  *flag.FlagSet
	config *AGUIConfig
	runner *runner.Runner
}

// NewLauncher creates a new AG-UI sublauncher that serves the /run_sse endpoint
// for streaming agent responses via Server-Sent Events.
func NewLauncher(appName string, opts ...Option) weblauncher.Sublauncher {
	config := &AGUIConfig{
		appName: appName,
	}
	for _, opt := range opts {
		opt(config)
	}

	fs := flag.NewFlagSet("agui", flag.ContinueOnError)
	fs.StringVar(&config.pathPrefix, "path_prefix", "/agui", "AG-UI API path prefix. Default is '/agui'.")

	return &aguiLauncher{
		flags:  fs,
		config: config,
	}
}

// Keyword returns the sublauncher keyword used for CLI dispatch.
func (l *aguiLauncher) Keyword() string {
	return "agui"
}

// Parse parses AG-UI-specific command-line flags from args and normalizes
// the path prefix to ensure it starts with "/" and has no trailing slash.
func (l *aguiLauncher) Parse(args []string) ([]string, error) {
	err := l.flags.Parse(args)
	if err != nil || !l.flags.Parsed() {
		return nil, fmt.Errorf("failed to parse agui flags: %v", err)
	}
	p := l.config.pathPrefix
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	l.config.pathPrefix = strings.TrimSuffix(p, "/")
	return l.flags.Args(), nil
}

// CommandLineSyntax returns a formatted string describing all available flags.
func (l *aguiLauncher) CommandLineSyntax() string {
	return util.FormatFlagUsage(l.flags)
}

// SimpleDescription returns a human-readable description of the sublauncher.
func (l *aguiLauncher) SimpleDescription() string {
	return "starts AG-UI protocol server for CopilotKit and other AG-UI compatible clients"
}

// SetupSubrouters registers the AG-UI endpoints on the router:
//   - POST /run_sse — SSE streaming endpoint for agent runs
//   - GET /capabilities — capability discovery endpoint (if configured)
//
// When CORS is configured, OPTIONS preflight is also handled for both routes.
func (l *aguiLauncher) SetupSubrouters(router *mux.Router, config *launcher.Config) error {
	// TODO: Support multi-tenant / multi-agent routing.
	// The runner is currently created once at setup for the single root agent,
	// which means one aguiLauncher instance serves exactly one agent. To support
	// multi-agent routing (e.g. /agui/{app_name}/run_sse), this would need to:
	//   1. Register path-based routes with an {app_name} variable.
	//   2. Extract app_name from the request in runSSEHandler.
	//   3. Call config.AgentLoader.LoadAgent(appName) per request to resolve
	//      the target agent dynamically.
	//   4. Create the runner per request (as the REST API controller does in
	//      server/adkrest/controllers/runtime.go RuntimeAPIController.getRunner).
	// Until then, deploy one aguiLauncher per agent, matching the A2A launcher
	// pattern which also binds to a single RootAgent at setup time.
	agentRunner, err := runner.New(runner.Config{
		AppName:           l.config.appName,
		Agent:             config.AgentLoader.RootAgent(),
		SessionService:    config.SessionService,
		ArtifactService:   config.ArtifactService,
		MemoryService:     config.MemoryService,
		PluginConfig:      config.PluginConfig,
		AutoCreateSession: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create agent runner: %w", err)
	}
	l.runner = agentRunner

	h := l.runSSEHandler()

	if l.config.cors != nil {
		h = l.corsMiddleware(h)
		router.Handle(l.config.pathPrefix+"/run_sse", h).Methods(http.MethodPost, http.MethodOptions)
	} else {
		router.Handle(l.config.pathPrefix+"/run_sse", h).Methods(http.MethodPost)
	}

	if l.config.capabilities != nil {
		capsHandler := l.capabilitiesHandler()
		if l.config.cors != nil {
			capsHandler = l.corsMiddleware(capsHandler)
			router.Handle(l.config.pathPrefix+"/capabilities", capsHandler).Methods(http.MethodGet, http.MethodOptions)
		} else {
			router.Handle(l.config.pathPrefix+"/capabilities", capsHandler).Methods(http.MethodGet)
		}
	}

	return nil
}

// UserMessage prints the AG-UI endpoint URL to the console on startup.
func (l *aguiLauncher) UserMessage(webURL string, printer func(v ...any)) {
	printer(fmt.Sprintf("       agui:  AG-UI SSE endpoint is available at %s%s/run_sse", webURL, l.config.pathPrefix))
}

// capabilitiesHandler returns an HTTP handler that serves the agent's
// declared capabilities as JSON.
func (l *aguiLauncher) capabilitiesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(l.config.capabilities); err != nil {
			http.Error(w, "failed to encode capabilities", http.StatusInternalServerError)
		}
	})
}

// corsMiddleware wraps an HTTP handler with CORS response headers derived
// from the launcher's CORSConfig. It short-circuits OPTIONS preflight
// requests with 204 No Content.
//
// When AllowCredentials is true, the middleware echoes the request's Origin
// header instead of using "*", because the CORS spec forbids wildcard origins
// with credentialed requests. When AllowCredentials is false and the only
// configured origin is "*", it returns "*" directly.
func (l *aguiLauncher) corsMiddleware(next http.Handler) http.Handler {
	corsCfg := l.config.cors

	allowedHeaders := "Content-Type, Authorization"
	if len(corsCfg.AllowedHeaders) > 0 {
		allowedHeaders = strings.Join(corsCfg.AllowedHeaders, ", ")
	}

	exposeHeaders := ""
	if len(corsCfg.ExposeHeaders) > 0 {
		exposeHeaders = strings.Join(corsCfg.ExposeHeaders, ", ")
	}

	isAllowedOrigin := func(origin string) bool {
		for _, allowed := range corsCfg.AllowedOrigins {
			if allowed == "*" || allowed == origin {
				return true
			}
		}
		return false
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && isAllowedOrigin(origin) {
			// When credentials are enabled, the spec requires the exact origin
			// (not "*"). Otherwise, use "*" only if it's the sole allowed origin.
			if corsCfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else if len(corsCfg.AllowedOrigins) == 1 && corsCfg.AllowedOrigins[0] == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			// Preflight: return allowed methods/headers and stop.
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Actual request: expose any configured response headers.
			if exposeHeaders != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
			}
		}

		// Preflight from a disallowed origin: still return 204 so the
		// browser gets a clean response; it will block because the
		// CORS headers are absent.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// convertMultimodalInput converts a non-text, non-binary InputContent (e.g.
// image, audio, video, document) to a genai.Part. These types use a nested
// source object in the AG-UI spec, but the Go SDK's InputContent struct
// doesn't have a Source field yet — so we check the flat fields (Data, URL,
// MimeType) which may be populated by future SDK versions, and fall back to
// an error if no usable data is found.
func convertMultimodalInput(ic types.InputContent) (*genai.Part, error) {
	// Inline base64 data (source.type = "data")
	if ic.Data != "" {
		dataBytes, err := base64.StdEncoding.DecodeString(ic.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 data: %w", err)
		}
		return &genai.Part{
			InlineData: &genai.Blob{
				Data:     dataBytes,
				MIMEType: ic.MimeType,
			},
		}, nil
	}

	// URL reference (source.type = "url")
	if ic.URL != "" {
		return &genai.Part{
			FileData: &genai.FileData{
				FileURI:  ic.URL,
				MIMEType: ic.MimeType,
			},
		}, nil
	}

	// TODO: The AG-UI Go SDK needs a Source field on InputContent to fully
	// support the new multimodal format (image/audio/video/document types
	// with nested { type, value, mimeType } source objects). Until then,
	// clients using the new format will hit this error. Track the Go SDK
	// update and remove this fallback once Source is available.
	return nil, fmt.Errorf("no data or url available (Go SDK may need Source field support)")
}

// runSSEHandler returns the HTTP handler for the AG-UI /run_sse endpoint.
//
// The handler has two phases separated by the SSE commitment point:
//   - Pre-SSE: request parsing, interceptors, validation.
//     Errors in this phase return standard HTTP error responses.
//   - Post-SSE: after SSE headers are written and RunStartedEvent is emitted.
//     Errors in this phase are delivered as RunErrorEvent on the SSE stream.
func (l *aguiLauncher) runSSEHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pre-SSE phase: errors use http.Error.

		var req types.RunAgentInput
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding AGUI request: %v", err)
			http.Error(w, "Invalid AGUI request payload", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		state := &streamState{}

		// Use client-provided IDs when available; generate otherwise.
		state.runID = req.RunID
		if state.runID == "" {
			state.runID = events.GenerateRunID()
		}
		state.threadID = req.ThreadID
		if state.threadID == "" {
			state.threadID = uuid.New().String()
		}

		// ADK session ID maps 1:1 with AG-UI threadID for conversation continuity.
		sessionID := state.threadID

		ctx := r.Context()
		callCtx := &CallContext{
			User: &User{
				Name: "agui-user",
			},
		}

		// Run Before interceptors, tracking how many succeeded so After
		// only runs for those (prevents calling After for interceptors
		// whose Before never ran or failed).
		var handlerErr error
		var succeeded int
		defer func() {
			for i := succeeded - 1; i >= 0; i-- {
				if afterErr := l.config.interceptors[i].After(ctx, callCtx, handlerErr); afterErr != nil {
					log.Printf("AGUI After interceptor error: %v", afterErr)
				}
			}
		}()
		for i, interceptor := range l.config.interceptors {
			var err error
			ctx, err = interceptor.Before(ctx, callCtx, &req, r)
			if err != nil {
				http.Error(w, "Interceptor rejected request: "+err.Error(), http.StatusInternalServerError)
				return
			}
			succeeded = i + 1
		}

		// Interceptors may populate callCtx.User; validate it's set.
		if callCtx == nil || callCtx.User == nil || callCtx.User.Name == "" {
			http.Error(w, "userID is required", http.StatusBadRequest)
			return
		}
		userID := callCtx.User.Name

		// Extract the last user message from the AG-UI request.
		// AG-UI sends the full conversation history; we only need the latest user turn
		// because ADK session service maintains its own history via threadID.
		var msg *genai.Content
		for i := len(req.Messages) - 1; i >= 0; i-- {
			message := req.Messages[i]
			if message.Role != types.RoleUser {
				continue
			}

			// Try multimodal array content first.
			// Handles both the legacy "binary" format (flat fields) and the new
			// typed formats ("image", "audio", "video", "document") which use a
			// nested source object. The Go SDK currently only defines InputContentTypeText
			// and InputContentTypeBinary; the new types are handled via the
			// source.value / source.mimeType path extracted from the raw JSON
			// (the Go SDK unmarshals unknown fields into the flat Data/URL/MimeType
			// fields when they're present at the top level, but the new format
			// nests them under "source" — so we fall back to the URL or Data
			// field which the SDK populates from the raw JSON).
			if inputContents, ok := message.ContentInputContents(); ok && len(inputContents) > 0 {
				parts := make([]*genai.Part, len(inputContents))
				for j, inputContent := range inputContents {
					switch inputContent.Type {
					case types.InputContentTypeText:
						parts[j] = genai.NewPartFromText(inputContent.Text)
					case types.InputContentTypeBinary:
						// Legacy binary format: AG-UI sends base64 in Data field.
						dataBytes, err := base64.StdEncoding.DecodeString(inputContent.Data)
						if err != nil {
							handlerErr = fmt.Errorf("failed to decode base64 binary data: %w", err)
							http.Error(w, handlerErr.Error(), http.StatusBadRequest)
							return
						}
						parts[j] = &genai.Part{
							InlineData: &genai.Blob{
								Data:        dataBytes,
								MIMEType:    inputContent.MimeType,
								DisplayName: inputContent.Filename,
							},
						}
					default:
						// New typed multimodal formats (image, audio, video, document).
						// These use a source object: { type: "data"|"url", value, mimeType }.
						// The Go SDK doesn't have a Source field yet, so the nested
						// source data won't be in the flat InputContent fields.
						// For now, check if Data or URL was populated (some SDK
						// versions may flatten these) and fall back gracefully.
						part, err := convertMultimodalInput(inputContent)
						if err != nil {
							handlerErr = fmt.Errorf("unsupported content type %q: %w", inputContent.Type, err)
							http.Error(w, handlerErr.Error(), http.StatusBadRequest)
							return
						}
						parts[j] = part
					}
				}
				msg = genai.NewContentFromParts(parts, genai.RoleUser)
				break
			}

			// Fall back to plain string content.
			if contentStr, ok := message.ContentString(); ok && contentStr != "" {
				msg = genai.NewContentFromText(contentStr, genai.RoleUser)
				break
			}

			handlerErr = fmt.Errorf("unsupported content type: %T", message.Content)
			http.Error(w, handlerErr.Error(), http.StatusBadRequest)
			return
		}

		if msg == nil {
			handlerErr = fmt.Errorf("no user message found in payload")
			http.Error(w, handlerErr.Error(), http.StatusBadRequest)
			return
		}

		// SSE commitment point: after this, errors become RunErrorEvent.

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			handlerErr = fmt.Errorf("failed to flush SSE headers: %w", err)
			http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
			return
		}

		e := newEmitter(ctx, w, sse.NewSSEWriter(), l.config.interceptors[:succeeded], callCtx)

		// emitError sends a RunErrorEvent on the SSE stream and marks the run as
		// finalized so that RunFinishedEvent is not also emitted.
		emitError := func(errMsg string) {
			e.emit(events.NewRunErrorEvent(errMsg, events.WithRunID(state.runID)))
			state.runFinalized = true
		}

		e.emit(events.NewRunStartedEvent(state.threadID, state.runID))
		if e.err != nil {
			handlerErr = fmt.Errorf("failed to write RunStartedEvent: %w", e.err)
			return
		}

		// TODO: Emit an initial StateSnapshotEvent here to establish baseline
		// state for the client. The AG-UI spec recommends sending a snapshot at
		// the start of an interaction so the frontend has the full state before
		// any deltas arrive. To implement:
		//   1. Load the session via config.SessionService (needs to be threaded
		//      through from the handler method's launcher.Config).
		//   2. Iterate session.State().All() to build a map[string]any.
		//   3. Emit: e.emit(events.NewStateSnapshotEvent(stateMap))
		// This is deferred because the session may not exist yet on the first
		// run (AutoCreateSession creates it inside runner.Run), so the snapshot
		// would need to come from the first event's session or a post-create
		// callback.

		// Stream ADK events, mapping each to AG-UI protocol events.
		cfg := agent.RunConfig{
			StreamingMode:             agent.StreamingModeSSE,
			SaveInputBlobsAsArtifacts: false,
		}

		// Forward initial state from the AG-UI request into the ADK session.
		// The frontend may send state (e.g. form values, UI context) that the
		// agent's tools or instructions can read via session state.
		var runOpts []runner.RunOption
		if stateMap, ok := req.State.(map[string]any); ok && len(stateMap) > 0 {
			runOpts = append(runOpts, runner.WithStateDelta(stateMap))
		}

		for ev, err := range l.runner.Run(ctx, userID, sessionID, msg, cfg, runOpts...) {
			if err != nil {
				emitError(err.Error())
				handlerErr = err
				break
			}
			if ev == nil {
				continue
			}

			if ev.ErrorMessage != "" {
				opts := []events.RunErrorOption{events.WithRunID(state.runID)}
				if ev.ErrorCode != "" {
					opts = append(opts, events.WithErrorCode(ev.ErrorCode))
				}
				e.emit(events.NewRunErrorEvent(ev.ErrorMessage, opts...))
				state.runFinalized = true
				handlerErr = fmt.Errorf("%s", ev.ErrorMessage)
				break
			}

			done, err := l.processEvent(e, ev, state)
			if err != nil {
				emitError(err.Error())
				handlerErr = err
				break
			}
			if done {
				break
			}
		}

		// TODO: Implement AG-UI interrupt resume protocol.
		// The emit half is done: adk_request_confirmation FunctionCalls are
		// detected and converted to RunFinished { outcome: { type: "interrupt" } }
		// with the original tool call emitted as ToolCallStart/Args/End for
		// the audit trail. The resume half requires:
		//   1. The AG-UI Go SDK to add a `Resume` field to RunAgentInput
		//      ([]ResumeEntry with interruptId, status, and payload).
		//   2. On a resumed run, extract req.Resume entries and for each:
		//      a. Look up the ADK confirmation call ID from the interrupt's
		//         metadata["adk"]["confirmationCallId"].
		//      b. Build a genai.FunctionResponse with:
		//           Name: toolconfirmation.FunctionCallName
		//           ID:   confirmationCallId
		//           Response: map[string]any{
		//             "confirmed": payload["approved"],
		//             "payload":   payload (or payload["editedArgs"]),
		//           }
		//      c. Inject the FunctionResponse into the ADK session as a user
		//         content event and restart the runner.
		//   3. Cancelled resumes (status: "cancelled") should map to
		//      confirmed=false with no payload.
		// See: https://docs.ag-ui.com/concepts/interrupts

		// Emit RunFinishedEvent only if no terminal event (RunError) was already sent.
		if !state.runFinalized {
			e.emit(events.NewRunFinishedEvent(state.threadID, state.runID))
		}
	})
}
