# Tool Auth Changes to ADK-Go

This document catalogs every addition and modification made to this ADK-Go fork to support the `adk_request_credential` protocol for tool authentication (primarily OAuth2). These changes enable both the REST/adk-web flow and the A2A flow.

The original (unmodified) ADK-Go is at `.debug/imported/adk-go-original` for reference.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [End-to-End Flow Diagrams](#end-to-end-flow-diagrams)
3. [New Package: `tool/toolauth`](#new-package-tooltoolauth)
4. [Auth Preprocessor: `internal/llminternal/other_processors.go`](#auth-preprocessor-internalllminternalother_processorsgo)
5. [Tool Context: `tool/tool.go` and `internal/toolinternal/context.go`](#tool-context-tooltoolgo-and-internaltoolinternalcontextgo)
6. [REST Layer: `server/adkrest/`](#rest-layer-serveradkrest)
7. [A2A Layer: `server/adka2a/`](#a2a-layer-serveradka2a)
8. [Dependency Changes](#dependency-changes)
9. [File-by-File Change Summary](#file-by-file-change-summary)

---

## Architecture Overview

The Python ADK natively emits `adk_request_credential` events when tools request OAuth. The Go ADK stores auth requests in `StateDelta` but previously had no mechanism to:

1. Transform those events into the `adk_request_credential` format clients expect.
2. Process the OAuth callback when the client sends back the authorization code.
3. Exchange the code for tokens and re-invoke the original tool.

The changes fall into four layers:

```
┌──────────────────────────────────────────────────────────────────┐
│  tool/toolauth (NEW)                                             │
│  Types, constants, auth URL generation, token exchange,          │
│  event building for both REST and A2A                            │
├──────────────────────────────────────────────────────────────────┤
│  internal/llminternal (MODIFIED)                                 │
│  authPreprocessor: handles OAuth callback, exchanges tokens,     │
│  re-invokes original tool                                        │
├──────────────────────────────────────────────────────────────────┤
│  server/adkrest (MODIFIED)                                       │
│  REST controllers: transform StateDelta auth events for adk-web, │
│  handle authCallbackUrl, normalize message keys                  │
├──────────────────────────────────────────────────────────────────┤
│  server/adka2a (MODIFIED + NEW)                                  │
│  A2A processor: detect auth-required, emit TaskStateAuthRequired,│
│  handle auth-required in input_required flow                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## End-to-End Flow Diagrams

### REST / adk-web Flow

```
User → Agent → Tool calls GetCredential → nil (no token)
                    │
                    ▼
              Tool calls RequestCredential
              → GenerateAuthRequest builds OAuth URL
              → Stores AuthConfig in StateDelta["adk_auth_request_<callID>"]
              → Tool returns "Pending User Authorization"
                    │
                    ▼
              Runner yields event with StateDelta
                    │
                    ▼
              REST Controller (RunSSEHandler / RunHandler)
              → IsAuthRequired(event) = true
              → ExtractAuthRequest → functionCallID, AuthConfig
              → BuildAuthRequestEvent → transformed event with:
                  - Content: FunctionCall(name="adk_request_credential", args={authConfig})
                  - LongRunningToolIDs: [functionCallID]
              → Sends transformed event to adk-web
                    │
                    ▼
              adk-web opens OAuth popup → User signs in → Provider redirects
                    │
                    ▼
              adk-web sends callback:
              → POST /run_sse with authCallbackUrl=<callback URL with ?code=...>
                OR newMessage with FunctionResponse(name="adk_request_credential")
                    │
                    ▼
              REST Controller
              → transformAuthCallback: reads session state for pending auth,
                builds FunctionResponse content via BuildAuthCallbackContent
                    │
                    ▼
              Runner invokes authPreprocessor
              → Finds FunctionResponse for "adk_request_credential"
              → Calls ExchangeAndStore: parses code, exchanges for tokens,
                stores at "temp:<credentialKey>"
              → Finds original tool call (e.g. get_user_info)
              → Re-invokes tool via handleFunctionCalls
                    │
                    ▼
              Tool calls GetCredential → returns stored token
              → Tool completes successfully
```

### A2A Flow

```
User → A2A Client → sendStreamingMessage → Executor → Runner → Tool
                    │
              (same as REST until StateDelta)
                    │
                    ▼
              eventProcessor.process
              → authRequiredProcessor.process(event)
              → IsAuthRequired(event) = true
              → ExtractAuthRequest → functionCallID, AuthConfig
              → BuildAuthRequestContentFromConfig → genai.Content + LongRunningToolIDs
              → Converts to A2A parts via ToA2AParts
              → Creates TaskStatusUpdateEvent with TaskStateAuthRequired
                    │
                    ▼
              A2A Client receives auth-required task status
              → Opens OAuth popup → User signs in → Provider redirects
                    │
                    ▼
              A2A Client sends callback via sendStreamingMessage
              → Message contains FunctionResponse with auth callback URL
                    │
                    ▼
              Executor.Execute → handleInputRequired
              → Recognizes TaskStateAuthRequired (treated like input-required)
              → Content flows to Runner
                    │
                    ▼
              Runner invokes authPreprocessor
              → (same as REST from here: ExchangeAndStore, re-invoke tool)
```

---

## New Package: `tool/toolauth`

This entire package is new. The original ADK-Go had no `tool/toolauth` directory.

### `toolauth.go` — Types and Constants

The package-level doc comment documents the full 5-step protocol. Key types:

| Type | Purpose |
|------|---------|
| `AuthConfig` | Main config struct with `RawAuthCredential` (static: client_id, secret, scopes) and `ExchangedAuthCredential` (dynamic: auth_uri on outbound, auth_response_uri on inbound). `CredentialKey` identifies stored tokens. |
| `AuthCredential` | Wraps `OAuth2Credential`, `APIKeyCredential`, `BearerTokenCredential`, `ServiceAccountCredential`. |
| `OAuth2Credential` | All OAuth2 fields: client_id, client_secret, auth_uri, token_uri, redirect_uri, auth_response_uri, state, scopes, access_token, refresh_token, expires_at. |
| `AuthCredentialType` | Enum: `OAUTH2`, `OPEN_ID_CONNECT`, `API_KEY`, `HTTP`, `SERVICE_ACCOUNT`. |
| `AuthToolArguments` | The args shape for the `adk_request_credential` FunctionCall. |
| `FunctionCallName` | Constant `"adk_request_credential"`. |

### `constants.go` — Key Prefixes

| Constant | Value | Purpose |
|----------|-------|---------|
| `CredentialStatePrefix` | `"temp:"` | Session state key prefix for stored tokens. Tools call `GetCredential` which reads `"temp:<credentialKey>"`. |
| `StateDeltaKeyPrefix` | `"adk_auth_request_"` | StateDelta key prefix. Full key: `"adk_auth_request_<functionCallID>"`. Links auth request to original tool call. |

### `auth_request.go` — Auth Event Detection and Building

| Function | Signature | Purpose |
|----------|-----------|---------|
| `GenerateAuthRequest` | `(cfg AuthConfig) (AuthConfig, error)` | Builds OAuth authorization URL using `oauth2.Config.AuthCodeURL`. Populates `ExchangedAuthCredential.OAuth2.AuthURI`. |
| `IsAuthRequired` | `(event *session.Event) bool` | Checks if event's StateDelta has any key with `StateDeltaKeyPrefix`. |
| `ExtractAuthRequest` | `(event *session.Event) (functionCallID, AuthConfig, bool)` | Parses StateDelta value into AuthConfig. Supports `map[string]any`, `*AuthConfig`, and `AuthConfig` value types. |
| `ExtractAuthRequestFromState` | `(state map[string]any) (functionCallID, AuthConfig, bool)` | Same as above but reads from session state map (used by A2A layer after events are committed). |
| `BuildAuthRequestContentFromConfig` | `(functionCallID, AuthConfig) (*genai.Content, []string)` | Builds `genai.Content` with `adk_request_credential` FunctionCall for A2A. Returns content + long-running tool IDs. Falls back to `GenerateAuthRequest` if no auth URI. |
| `BuildAuthCallbackContent` | `(functionCallID, AuthConfig, callbackURL) *genai.Content` | Builds user message with `adk_request_credential` FunctionResponse for the callback. Used by REST `transformAuthCallback`. |
| `BuildAuthRequestEvent` | `(sourceEvent, functionCallID, AuthConfig) *session.Event` | Builds full `session.Event` replacing the original. Used by REST controllers. Preserves source event's ID, branch, timestamp, invocationID. |
| `toFrontendAuthConfigMap` | `(AuthConfig) map[string]any` | Converts to camelCase keys for adk-web/clients. |
| `oauth2CredToFrontendMap` | `(*OAuth2Credential) map[string]any` | Converts OAuth2 fields to camelCase. |

### `handler.go` — Token Exchange and Key Normalization

| Function | Signature | Purpose |
|----------|-----------|---------|
| `AuthConfigFromResponseMap` | `(map[string]any) (AuthConfig, error)` | Parses FunctionResponse payload into AuthConfig. Normalizes camelCase/snake_case keys via `normalizeAuthConfigKeys`. |
| `normalizeAuthConfigKeys` | `(map[string]any) map[string]any` | Recursive camelCase → snake_case conversion for known auth keys. |
| `camelToSnake` | `(string) string` | Lookup table mapping ~20 known camelCase keys to snake_case. |
| `ExchangeAndStore` | `(ctx, AuthConfig, session.State) error` | **Core token exchange.** Parses `auth_response_uri` for code, merges exchanged/raw credentials for client_id/secret, calls `oauth2.Config.Exchange`, stores token at `"temp:<credentialKey>"`. |
| `ExchangeAndStoreServiceAccount` | `(ctx, AuthConfig, session.State) error` | Non-interactive flow using service account JSON key via `google.CredentialsFromJSON`. |

#### ExchangeAndStore Credential Resolution

`ExchangeAndStore` merges two credential sources:

- **ExchangedAuthCredential**: callback-specific fields (`auth_response_uri`, `redirect_uri`)
- **RawAuthCredential**: static tool config (`client_id`, `client_secret`, `token_uri`)

This is necessary because different clients send credentials differently:
- adk-web sends everything in `exchangedAuthCredential`
- a2a-playground includes `rawAuthCredential` with static secrets and only the callback URL in `exchangedAuthCredential`

The function uses a fallback chain: exchanged → raw → defaults for each field.

---

## Auth Preprocessor: `internal/llminternal/other_processors.go`

**Before**: `authPreprocessor` was a stub with `// TODO: implement`.

**After**: Full implementation that handles the server-side OAuth callback.

### What It Does

The preprocessor runs before the LLM call on every invocation. On normal invocations (no OAuth callback), it returns immediately. When it finds an OAuth callback:

1. **Scans session events** (newest first) for a user-authored `FunctionResponse` named `adk_request_credential`.
2. **Parses the auth config** from the response. Handles three client formats:
   - Direct map (a2a-playground sends auth config directly)
   - Wrapped as JSON string in `{"response": "<json>"}` (adk-web format)
   - Wrapped as nested map in `{"response": {...}}` (alternate adk-web format)
3. **Calls `ExchangeAndStore`** to exchange the authorization code for tokens and store in session state.
4. **Finds the original tool call** by matching the `FunctionResponse.ID` to a `FunctionCall` in session history (skipping `adk_request_credential` calls).
5. **Re-invokes the original tool** via `handleFunctionCalls`. The tool's `GetCredential` now finds the stored token and completes successfully.

### Helper: `findOriginalToolCall`

Searches session events (newest first) for a `FunctionCall` with the given ID, skipping `adk_request_credential` calls. The ID linking mechanism: when a tool requests credentials, the `adk_request_credential` FunctionCall reuses the original tool's call ID, so the callback FunctionResponse uses the same ID.

---

## Tool Context: `tool/tool.go` and `internal/toolinternal/context.go`

### `tool/tool.go` — Interface Change

**Added** `SessionState()` method to the `tool.Context` interface:

```go
// SessionState returns the session state for the current invocation.
// Tools can use this to read credentials or other state (e.g. for OAuth).
// May return nil if no session is available.
SessionState() session.ReadonlyState
```

This is required by `CredentialHelper.GetCredential` to read stored tokens from `"temp:<credentialKey>"` in session state.

### `internal/toolinternal/context.go` — Implementation

**Added** `SessionState()` method to `toolContext`:

```go
func (c *toolContext) SessionState() session.ReadonlyState {
    if c.invocationContext.Session() == nil {
        return nil
    }
    return c.invocationContext.Session().State()
}
```

---

## REST Layer: `server/adkrest/`

### `server/adkrest/internal/models/runtime.go` — Request Model

**Added two fields** to `RunAgentRequest`:

```go
// AuthCallbackUrl is the full OAuth redirect URL when the client loads after
// the OAuth provider redirect.
AuthCallbackUrl string `json:"authCallbackUrl,omitempty"`

// FunctionCallEventId is sent by adk-web for OAuth callback requests.
FunctionCallEventId string `json:"functionCallEventId,omitempty"`
```

### `server/adkrest/controllers/runtime.go` — Controllers

**Multiple changes** to support auth event transformation and callback handling:

#### 1. Auth event transformation in `RunHandler` and `RunSSEHandler`

Both handlers now check each event before sending:

```go
if toolauth.IsAuthRequired(event) {
    if fnCallID, authCfg, ok := toolauth.ExtractAuthRequest(event); ok {
        if authEvent := toolauth.BuildAuthRequestEvent(event, fnCallID, authCfg); authEvent != nil {
            event = authEvent
        }
    }
}
```

This replaces the raw StateDelta event with an `adk_request_credential` FunctionCall event that adk-web recognizes.

#### 2. Auth callback handling in `runAgent` and `RunSSEHandler`

Both check for `authCallbackUrl` and transform the message:

```go
if runAgentRequest.AuthCallbackUrl != "" {
    if transformed := c.transformAuthCallback(ctx, runAgentRequest); transformed != nil {
        msg = transformed
    }
}
```

#### 3. New function: `transformAuthCallback`

Bridges adk-web's `authCallbackUrl` to the internal protocol:
1. Fetches the session to find the pending auth request in state.
2. Builds a `FunctionResponse` message via `BuildAuthCallbackContent`.
3. The runner then processes this through `authPreprocessor`.

#### 4. New function: `decodeRequestBody`

Replaces the original simple `json.Decode` with:
- `normalizeNewMessageParts`: converts snake_case part keys (`function_response`, `function_call`) to camelCase (`functionResponse`, `functionCall`) for `genai.Part` compatibility.
- `authCallbackUrl` from query parameter fallback.

#### 5. New function: `normalizeNewMessageParts`

Fixes the serialization mismatch between adk-web (Python protobuf convention: snake_case) and the Go genai SDK (camelCase JSON tags).

---

## A2A Layer: `server/adka2a/`

### `server/adka2a/auth_required.go` — NEW FILE

The `authRequiredProcessor` detects tool auth requests during A2A event processing:

1. Checks each event for StateDelta keys with `adk_auth_request_*` prefix.
2. Extracts functionCallID and AuthConfig.
3. Calls `BuildAuthRequestContentFromConfig` to generate `adk_request_credential` content.
4. Converts to A2A parts.
5. Creates `TaskStatusUpdateEvent` with `TaskStateAuthRequired` and `Final=true`.

### `server/adka2a/processor.go` — MODIFIED

**Added** `authRequiredProcessor` field to `eventProcessor`:

```go
authRequiredProcessor *authRequiredProcessor
```

**Modified** `newEventProcessor` to initialize it:

```go
authRequiredProcessor: newAuthRequiredProcessor(reqCtx),
```

**Modified** `process` to run auth processing before input processing:

```go
event, err = p.authRequiredProcessor.process(event)
// ...
event, err = p.inputRequiredProcessor.process(event)
```

**Modified** `makeFinalStatusUpdate` priority to include auth-required:

```go
// Priority: failed > authRequired > inputRequired > completed
for _, event := range []*a2a.TaskStatusUpdateEvent{
    p.failedEvent,
    p.authRequiredProcessor.event,
    p.inputRequiredProcessor.event,
} { ... }
```

**Removed** the `eventToArtifactTransform` interface and `eventToArtifact` field (refactored artifact handling inline).

### `server/adka2a/events.go` — MODIFIED

**Modified** `taskStatusUpdateToEvent` to treat `TaskStateAuthRequired` like `TaskStateInputRequired`:

```go
// Before:
isTerminal := task.Status.State.Terminal() || task.Status.State == a2a.TaskStateInputRequired
// ...
if task.Status.State == a2a.TaskStateInputRequired {

// After:
isTerminal := task.Status.State.Terminal() || task.Status.State == a2a.TaskStateInputRequired || task.Status.State == a2a.TaskStateAuthRequired
// ...
if task.Status.State == a2a.TaskStateInputRequired || task.Status.State == a2a.TaskStateAuthRequired {
```

Both are input-like terminal states: the agent waits for the client's response (OAuth callback or tool input) before continuing.

### `server/adka2a/input_required.go` — MODIFIED

**Modified** `handleInputRequired` to also handle `TaskStateAuthRequired`:

```go
// Before:
if task.Status.State != a2a.TaskStateInputRequired || statusMsg == nil {

// After:
if (task.Status.State != a2a.TaskStateInputRequired && task.Status.State != a2a.TaskStateAuthRequired) || statusMsg == nil {
```

Auth-required tasks follow the same response flow as input-required tasks.

### `server/adka2a/executor.go` — MODIFIED

**Modified** the `Executor` doc comment to include auth-required in the terminal state documentation:

```
// Else if StateDelta contains adk_auth_request_*, produce a TaskStatusUpdateEvent with TaskStateAuthRequired.
```

---

## Dependency Changes

### `go.mod` / `go.sum`

Added `golang.org/x/oauth2` dependency (used by `GenerateAuthRequest` and `ExchangeAndStore` for OAuth2 flows via `oauth2.Config`).

---

## File-by-File Change Summary

| File | Status | What Changed |
|------|--------|--------------|
| **`tool/toolauth/toolauth.go`** | NEW | Package doc, types (`AuthConfig`, `AuthCredential`, `OAuth2Credential`, etc.), constants (`FunctionCallName`). |
| **`tool/toolauth/constants.go`** | NEW | `CredentialStatePrefix` (`"temp:"`), `StateDeltaKeyPrefix` (`"adk_auth_request_"`). |
| **`tool/toolauth/auth_request.go`** | NEW | `GenerateAuthRequest`, `IsAuthRequired`, `ExtractAuthRequest`, `ExtractAuthRequestFromState`, `BuildAuthRequestContentFromConfig`, `BuildAuthCallbackContent`, `BuildAuthRequestEvent`, `toFrontendAuthConfigMap`, `oauth2CredToFrontendMap`. |
| **`tool/toolauth/handler.go`** | NEW | `AuthConfigFromResponseMap`, `normalizeAuthConfigKeys`, `camelToSnake`, `ExchangeAndStore`, `ExchangeAndStoreServiceAccount`. |
| **`tool/tool.go`** | MODIFIED | Added `SessionState() session.ReadonlyState` to `Context` interface. |
| **`internal/toolinternal/context.go`** | MODIFIED | Added `SessionState()` implementation on `toolContext`. |
| **`internal/llminternal/other_processors.go`** | MODIFIED | Implemented `authPreprocessor` (was a TODO stub). Added `findOriginalToolCall`. New imports: `encoding/json`, `fmt`, `google.golang.org/genai`, `tool`, `tool/toolauth`, `internal/utils`. |
| **`server/adkrest/internal/models/runtime.go`** | MODIFIED | Added `AuthCallbackUrl` and `FunctionCallEventId` fields to `RunAgentRequest`. |
| **`server/adkrest/controllers/runtime.go`** | MODIFIED | Auth event transformation in `RunHandler`/`RunSSEHandler`. New `transformAuthCallback`, `decodeRequestBody`, `normalizeNewMessageParts`. Auth callback URL handling in `runAgent`/`RunSSEHandler`. New imports: `bytes`, `io`, `maps`, `tool/toolauth`. |
| **`server/adka2a/auth_required.go`** | NEW | `authRequiredProcessor` struct with `process` method. Detects auth requests, builds `TaskStateAuthRequired` events. |
| **`server/adka2a/processor.go`** | MODIFIED | Added `authRequiredProcessor` to `eventProcessor`. Auth processing in `process()`. Updated `makeFinalStatusUpdate` priority. Refactored artifact handling (removed `eventToArtifactTransform` interface). |
| **`server/adka2a/events.go`** | MODIFIED | `taskStatusUpdateToEvent` now treats `TaskStateAuthRequired` as input-like terminal state. |
| **`server/adka2a/input_required.go`** | MODIFIED | `handleInputRequired` now also handles `TaskStateAuthRequired`. |
| **`server/adka2a/executor.go`** | MODIFIED | Updated doc comment to document auth-required terminal state. |
| **`go.mod`** | MODIFIED | Added `golang.org/x/oauth2` dependency. |
| **`go.sum`** | MODIFIED | Updated checksums for new dependencies. |

### Files with Non-Auth Changes

These files also differ between the fork and original but the changes are unrelated to tool auth (version bumps, telemetry refactoring, test file renames, etc.):

- `CONTRIBUTING.md`, `agent/agent.go`, `agent/remoteagent/*` — upstream version changes
- `internal/telemetry/*`, `telemetry/*` — telemetry refactoring (rename from "telemetry" to "tracing")
- `internal/llminternal/base_flow.go` — structural changes (auth preprocessor was already in the pipeline)
- `plugin/functioncallmodifier/plugin.go` — upstream changes
- `server/adkrest/handler.go`, `server/adkrest/internal/routers/debug.go` — unrelated routing changes
- `server/adka2a/metadata.go`, `server/adka2a/executor_test.go`, `server/adka2a/processor_test.go` — refactoring
- `session/database/storage_session.go` — upstream changes
- `cmd/launcher/web/webui/webui.go` — path prefix change (`/ui/` config)

---

## Python-Parity Refactor

This section documents the second phase of changes that align the Go ADK auth handling with the Python SDK pattern. The key change is moving from StateDelta-based auth signaling to a dedicated `EventActions.RequestedAuthConfigs` field with `tool.Context.RequestCredential`/`GetAuthResponse` methods.

### Architecture Change

**Before (StateDelta workaround):**
```
Tool → CredentialHelper → StateDelta["adk_auth_request_<callID>"] = config
  → REST/A2A transport scans StateDelta → transforms event → client
```

**After (dedicated EventActions field):**
```
Tool → toolCtx.RequestCredential(cfg) → EventActions.RequestedAuthConfigs[callID] = cfg
  → generateAuthEvent in LLM flow → adk_request_credential event → transport forwards → client
```

The transport layer no longer needs to scan StateDelta and transform events. Auth events are generated in the LLM flow layer (like confirmation events), and the transport layer forwards them as-is.

### End-to-End Flow (New Architecture)

```
1. Tool calls toolCtx.GetAuthResponse(cfg)
   → Checks session state for "temp:<credentialKey>"
   → Not found: returns (nil, nil) — pure read, no side effects

2. Tool checks for nil and explicitly calls toolCtx.RequestCredential(cfg)
   → Generates OAuth URL via GenerateAuthRequest
   → Stores config in EventActions.RequestedAuthConfigs[functionCallID]
   → Sets SkipSummarization = true

3. Tool returns "Pending User Authorization"

4. LLM flow (base_flow.go) after handleFunctionCalls:
   → generateAuthEvent checks ev.Actions.RequestedAuthConfigs
   → Calls BuildAuthRequestContentFromConfig for each entry
   → Yields adk_request_credential event with LongRunningToolIDs

5. Transport layer (REST or A2A):
   → REST: sends event as-is (already has correct content)
   → A2A: authRequiredProcessor detects RequestedAuthConfigs,
     emits TaskStateAuthRequired

6. Client handles OAuth popup → user signs in → callback

7. Client sends callback → authPreprocessor (unchanged):
   → Parses FunctionResponse for adk_request_credential
   → ExchangeAndStore exchanges code for tokens
   → Stores tokens at "temp:<credentialKey>"
   → Re-invokes original tool

8. Tool calls toolCtx.GetAuthResponse(cfg)
   → Finds stored token → returns AuthCredential
   → Tool completes successfully
```

### Import Cycle Resolution: `tool/toolauth` as Leaf Package

Adding `RequestedAuthConfigs map[string]toolauth.AuthConfig` to `session.EventActions` requires `session` to import `tool/toolauth`. Previously `tool/toolauth` imported `session`, which would create a cycle.

**Solution:** Make `tool/toolauth` a leaf package (same pattern as `tool/toolconfirmation`):

```
session ──imports──▶ tool/toolauth (leaf: NO session import)
session ──imports──▶ tool/toolconfirmation (leaf: NO session import)
tool ──imports──▶ tool/toolauth + tool/toolconfirmation + session
```

**What changed in `tool/toolauth`:**

| Change | Details |
|--------|---------|
| Added `StateWriter` interface | `type StateWriter interface { Set(key string, value any) error }`. `session.State` implicitly satisfies this. Used by `ExchangeAndStore` and `ExchangeAndStoreServiceAccount` instead of `session.State`. |
| Removed `IsAuthRequired(event)` | Replaced by checking `event.Actions.RequestedAuthConfigs` directly + `IsAuthRequiredInStateDelta(map)` for backward compat. |
| Removed `ExtractAuthRequest(event)` | Replaced by iterating `event.Actions.RequestedAuthConfigs` + `ExtractAuthRequestFromState(map)` for backward compat. |
| Removed `BuildAuthRequestEvent(event)` | Replaced by `generateAuthEvent` in LLM flow layer. |
| Added `IsAuthRequiredInStateDelta(map)` | Same logic as old `IsAuthRequired` but takes `map[string]any` directly (no session dependency). |
| Removed `session` import | Package now only imports `encoding/json`, `fmt`, `golang.org/x/oauth2`, `google.golang.org/genai`. |

### New `tool.Context` Methods

Added to the `tool.Context` interface in `tool/tool.go`:

| Method | Signature | Purpose |
|--------|-----------|---------|
| `RequestCredential` | `(cfg toolauth.AuthConfig) error` | Generates the OAuth URL, stores config in `EventActions.RequestedAuthConfigs[functionCallID]`, sets `SkipSummarization = true`. Auth equivalent of `RequestConfirmation`. |
| `GetAuthResponse` | `(cfg toolauth.AuthConfig) (*toolauth.AuthCredential, error)` | Pure read: checks session state for stored tokens. Returns them if found, or `(nil, nil)` if not. Does NOT call `RequestCredential` — the decision to initiate auth is left to the tool developer. Matches the `adk-python` pattern where `get_auth_response` and `request_credential` are independent methods. |

**Tool usage pattern (replaces CredentialHelper):**

```go
// Before (CredentialHelper):
helper := agenttoolauth.NewCredentialHelper(config, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
cred, err := helper.GetCredential(toolCtx)
if cred == nil { helper.RequestCredential(toolCtx) }

// After (tool.Context — two independent calls, matching adk-python):
cred, err := toolCtx.GetAuthResponse(myConfig)
if err != nil { return nil, err }
if cred == nil {
    // Explicitly request credential — developer controls when to initiate auth.
    if err := toolCtx.RequestCredential(myConfig); err != nil { return nil, err }
    return "Pending authorization", nil
}
// use cred.OAuth2.AccessToken
```

### `AuthCodeOptions` on `AuthConfig`

OAuth options (e.g. `oauth2.AccessTypeOffline`, `oauth2.ApprovalForce`) are now specified directly on `AuthConfig` rather than passed to a helper:

```go
var myConfig = toolauth.AuthConfig{
    CredentialKey: "my_tool",
    AuthCodeOptions: []oauth2.AuthCodeOption{
        oauth2.AccessTypeOffline,
        oauth2.ApprovalForce,
    },
    RawAuthCredential: &toolauth.AuthCredential{...},
}
```

`GenerateAuthRequest` passes these to `oauth2.Config.AuthCodeURL(state, cfg.AuthCodeOptions...)`.

### `generateAuthEvent` in LLM Flow

New function in `internal/llminternal/functions.go` that mirrors `generateRequestConfirmationEvent`:

- Checks `functionResponseEvent.Actions.RequestedAuthConfigs`
- For each entry, calls `toolauth.BuildAuthRequestContentFromConfig(functionCallID, authConfig)`
- Builds a `session.Event` with `LongRunningToolIDs` for client interaction
- Wired into `base_flow.go` after `handleFunctionCalls` returns (replacing the TODO comment)

`mergeEventActions` in `base_flow.go` also merges `RequestedAuthConfigs` (same pattern as `RequestedToolConfirmations`).

### Updated Consumers (Dual-Path Detection)

Both `server/adka2a/auth_required.go` and `server/adkrest/controllers/runtime.go` now use dual-path detection:

1. **Primary:** Check `event.Actions.RequestedAuthConfigs` (new `tool.Context` path)
2. **Fallback:** Check `event.Actions.StateDelta` via `IsAuthRequiredInStateDelta` + `ExtractAuthRequestFromState` (legacy CredentialHelper path)

### Backward Compatibility

| Component | Backward Compat |
|-----------|----------------|
| `StateDeltaKeyPrefix` | Retained with deprecation comment. Old tools still work. |
| `ExtractAuthRequestFromState` | Still available for StateDelta parsing. |
| `IsAuthRequiredInStateDelta` | Replaces `IsAuthRequired(event)` for StateDelta checking. |
| `authPreprocessor` | Unchanged. Still handles OAuth callbacks from all clients. |
| `ExchangeAndStore` | Signature changed (`session.State` → `StateWriter`), but `session.State` implicitly satisfies `StateWriter`. |
| `BuildAuthRequestContentFromConfig` | Unchanged. Still builds `genai.Content` for A2A. |
| `BuildAuthCallbackContent` | Unchanged. Still builds callback FunctionResponse. |

### File Changes (Python-Parity Phase)

| File | Change |
|------|--------|
| `tool/toolauth/toolauth.go` | Added `StateWriter` interface, `AuthCodeOptions` field, updated package doc. |
| `tool/toolauth/auth_request.go` | Removed `IsAuthRequired`, `ExtractAuthRequest`, `BuildAuthRequestEvent`. Added `IsAuthRequiredInStateDelta`. Removed `session` import. |
| `tool/toolauth/handler.go` | Changed `ExchangeAndStore`/`ExchangeAndStoreServiceAccount` to use `StateWriter`. Removed `session` import. |
| `tool/toolauth/constants.go` | Added deprecation comment on `StateDeltaKeyPrefix`. |
| `session/session.go` | Added `RequestedAuthConfigs map[string]toolauth.AuthConfig` to `EventActions`. Added `tool/toolauth` import. |
| `tool/tool.go` | Added `RequestCredential(cfg)` and `GetAuthResponse(cfg)` to `Context` interface. Added `tool/toolauth` import. |
| `internal/toolinternal/context.go` | Implemented `RequestCredential` and `GetAuthResponse` on `toolContext`. |
| `internal/llminternal/functions.go` | Added `generateAuthEvent` function. |
| `internal/llminternal/base_flow.go` | Wired `generateAuthEvent`, updated `mergeEventActions` for `RequestedAuthConfigs`. |
| `server/adka2a/auth_required.go` | Updated to dual-path detection (RequestedAuthConfigs + StateDelta fallback). |
| `server/adkrest/controllers/runtime.go` | Updated to use `IsAuthRequiredInStateDelta`/`ExtractAuthRequestFromState` (legacy fallback only). |
