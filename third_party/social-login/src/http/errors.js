export class ServiceError extends Error {
  constructor(code, message, status = 500, details) {
    super(message);
    this.name = "ServiceError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function statusForLogin(result) {
  if (result.ok) return 200;
  if (result.rateLimited) return 429;
  if (result.failureType === "profile_busy") return 409;
  if (result.failureType === "service_unavailable") return 503;
  return 401;
}
