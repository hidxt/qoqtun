package protocol

// Protocol error codes (04-protocol-v1.md §5).
const (
	ErrCodeProtocol           = "ERR_PROTOCOL"
	ErrCodeVersionUnsupported = "ERR_VERSION_UNSUPPORTED"
	ErrCodeAuthFailed         = "ERR_AUTH_FAILED"
	ErrCodeCertExpired        = "ERR_CERT_EXPIRED"
	ErrCodeCertRevoked        = "ERR_CERT_REVOKED"
	ErrCodeTokenInvalid       = "ERR_TOKEN_INVALID"
	ErrCodeTokenExpired       = "ERR_TOKEN_EXPIRED"
	ErrCodeTokenUsed          = "ERR_TOKEN_USED"
	ErrCodePortNotAllowed     = "ERR_PORT_NOT_ALLOWED"
	ErrCodePortInUse          = "ERR_PORT_IN_USE"
	ErrCodeTunnelLimit        = "ERR_TUNNEL_LIMIT"
	ErrCodeConnLimit          = "ERR_CONN_LIMIT"
	ErrCodeRateLimited        = "ERR_RATE_LIMITED"
	ErrCodeUDPSessionLimit    = "ERR_UDP_SESSION_LIMIT"
	ErrCodeTargetNotAllowed   = "ERR_TARGET_NOT_ALLOWED"
	ErrCodeNameInvalid        = "ERR_NAME_INVALID"
	ErrCodeNameConflict       = "ERR_NAME_CONFLICT"
	ErrCodeInternal           = "ERR_INTERNAL"
)

// NewError builds a protocol error. Fatal errors close the connection.
func NewError(code, message string, fatal bool) *Error {
	return &Error{Code: code, Message: message, Fatal: fatal}
}

// ProtocolError is a shorthand for a fatal ERR_PROTOCOL error.
func ProtocolError(message string) *Error {
	return NewError(ErrCodeProtocol, message, true)
}

// VersionUnsupportedError reports an incompatible protocol version.
func VersionUnsupportedError() *Error {
	return NewError(ErrCodeVersionUnsupported, "unsupported protocol version", true)
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}
