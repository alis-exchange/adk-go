package toolauth

// CredentialStatePrefix is the prefix for credential keys in session state. After a
// successful token exchange, the credential is stored at "temp:<credentialKey>". Tools
// call GetCredential(credentialKey) which reads from this prefixed key. The "temp:" prefix
// indicates these are transient session-scoped credentials, not persisted across sessions.
const CredentialStatePrefix = "temp:"

// StateDeltaKeyPrefix is the prefix for keys in EventActions.StateDelta when a tool
// requests credential via the adk_request_credential protocol. The full key is
// StateDeltaKeyPrefix + functionCallID, e.g. "adk_auth_request_abc123". The functionCallID
// links the auth request back to the original tool FunctionCall so the preprocessor can
// re-invoke the correct tool after token exchange.
const StateDeltaKeyPrefix = "adk_auth_request_"
