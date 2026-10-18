export class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.statusCode = status;
    this.code = code;
  }
}

export const httpError = (status, code, message) => new HttpError(status, code, message);
