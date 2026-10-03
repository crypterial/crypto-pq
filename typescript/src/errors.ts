export type ErrorCode =
  | "INVALID_LENGTH"
  | "INVALID_ENCODING"
  | "ALGORITHM_MISMATCH"
  | "INVALID_PUBLIC_KEY"
  | "INVALID_PRIVATE_KEY"
  | "INVALID_CONTEXT"
  | "INVALID_OPTION"
  | "RNG_FAILURE"
  | "SELF_TEST_FAILED"
  | "KEY_EXHAUSTED"
  | "STATE_PERSIST_FAILED"
  | "STATE_CONFLICT"
  | "UNSUPPORTED";

export class CryptoPQError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);

    this.name = "CryptoPQError";

    this.code = code;
  }
}
