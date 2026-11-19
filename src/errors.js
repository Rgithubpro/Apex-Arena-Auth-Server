export class HttpError extends Error {
  /** `extra` is merged into the JSON answer (e.g. { public_reason } for bans). */
  constructor(status, code, message, extra) {
    super(message || code);
    this.statusCode = status;
    this.code = code;
    this.extra = extra;
  }
}

export const httpError = (status, code, message, extra) => new HttpError(status, code, message, extra);
