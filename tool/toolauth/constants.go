package toolauth

// CredentialStatePrefix is the prefix for credential keys in session state.
const CredentialStatePrefix = "temp:"

// StateDeltaKeyPrefix is the prefix for keys in EventActions.StateDelta when a tool
// requests credential via the adk_request_credential protocol. The full key is
// StateDeltaKeyPrefix + functionCallID.
const StateDeltaKeyPrefix = "adk_auth_request_"
