export interface HttpErrorOptions {
  /** Extra response headers. */
  headers?: Record<string, string>;
  /** Extra fields merged into the JSON error body. */
  extra?: Record<string, unknown>;
}

/** An error that maps directly to an HTTP response. */
export class HttpError extends Error {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly extra: Record<string, unknown>;

  constructor(status: number, message: string, options: HttpErrorOptions = {}) {
    super(message);
    this.status = status;
    this.headers = options.headers ?? {};
    this.extra = options.extra ?? {};
  }
}
