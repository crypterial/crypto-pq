package cryptopq

type ErrorCode string

const (
	INVALID_LENGTH       ErrorCode = "INVALID_LENGTH"
	INVALID_ENCODING     ErrorCode = "INVALID_ENCODING"
	ALGORITHM_MISMATCH   ErrorCode = "ALGORITHM_MISMATCH"
	INVALID_PUBLIC_KEY   ErrorCode = "INVALID_PUBLIC_KEY"
	INVALID_PRIVATE_KEY  ErrorCode = "INVALID_PRIVATE_KEY"
	INVALID_CONTEXT      ErrorCode = "INVALID_CONTEXT"
	INVALID_OPTION       ErrorCode = "INVALID_OPTION"
	RNG_FAILURE          ErrorCode = "RNG_FAILURE"
	SELF_TEST_FAILED     ErrorCode = "SELF_TEST_FAILED"
	KEY_EXHAUSTED        ErrorCode = "KEY_EXHAUSTED"
	STATE_PERSIST_FAILED ErrorCode = "STATE_PERSIST_FAILED"
	STATE_CONFLICT       ErrorCode = "STATE_CONFLICT"
	UNSUPPORTED          ErrorCode = "UNSUPPORTED"
)

func (c ErrorCode) Error() string {
	return "cryptopq: " + string(c)
}

type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string {
	return "cryptopq: " + string(e.Code) + ": " + e.Message
}

func (e *Error) Is(target error) bool {
	code, ok := target.(ErrorCode)

	return ok && code == e.Code
}

func newError(code ErrorCode, message string) error {
	return &Error{Code: code, Message: message}
}

func invalidEncoding(message string) error {
	return newError(INVALID_ENCODING, message)
}

func invalidOption(message string) error {
	return newError(INVALID_OPTION, message)
}

func mismatch(message string) error {
	return newError(INVALID_PRIVATE_KEY, message)
}
