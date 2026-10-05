export const API_VERSION = "v1";

export function success(data) {
  return { version: API_VERSION, ok: true, data };
}

export function failure(code, message, details) {
  return {
    version: API_VERSION,
    ok: false,
    error: { code, message, ...(details ? { details } : {}) },
  };
}
