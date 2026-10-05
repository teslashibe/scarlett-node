import http from "node:http";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { failure, success } from "./http/envelopes.js";
import { ServiceError } from "./http/errors.js";
import { SocialLoginService } from "./service.js";

const MAX_BODY_BYTES = 1_048_576;
const PORT = Number.parseInt(process.env.PORT || "8090", 10);
const service = new SocialLoginService();
const bearerToken = (process.env.SOCIAL_LOGIN_BEARER_TOKEN || "").trim();

function authorize(req, token = bearerToken) {
  if (!token) {
    throw new ServiceError("auth_unavailable", "bearer authentication is not configured", 503);
  }
  const header = req.headers.authorization || "";
  const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
  const expectedHash = crypto.createHash("sha256").update(token).digest();
  const suppliedHash = crypto.createHash("sha256").update(supplied).digest();
  if (!supplied || !crypto.timingSafeEqual(expectedHash, suppliedHash)) {
    throw new ServiceError("unauthorized", "valid bearer authentication is required", 401);
  }
}

function profileDeleteParameters(rawURL) {
  const pathname = new URL(rawURL, "http://social-login.invalid").pathname;
  const match = /^\/v1\/profiles\/([^/]+)\/([^/]+)$/.exec(pathname);
  if (!match) return undefined;
  try {
    return { platform: decodeURIComponent(match[1]), profile_key: decodeURIComponent(match[2]) };
  } catch {
    throw new ServiceError("invalid_request", "profile path is not valid URL encoding", 400);
  }
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readJSON(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      throw new ServiceError("request_too_large", "request body exceeds 1 MiB", 413);
    }
    chunks.push(chunk);
  }
  try {
    const body = Buffer.concat(chunks).toString("utf8");
    return JSON.parse(body || "{}");
  } catch {
    throw new ServiceError("invalid_json", "request body is not valid JSON", 400);
  }
}

export function createServer(activeService = service, token = bearerToken) {
  return http.createServer(async (req, res) => {
    const controller = new AbortController();
    req.once("aborted", () => controller.abort());
    res.once("close", () => {
      if (!res.writableEnded) controller.abort();
    });
    try {
      if (req.method === "GET" && req.url === "/v1/health") return json(res, 200, success(activeService.health()));
      if (req.method === "GET" && req.url === "/v1/ready") {
        const ready = await activeService.ready();
        return json(res, ready.status === "ready" ? 200 : 503, success(ready));
      }
      if (req.method === "GET" && req.url === "/v1/platforms") {
        return json(res, 200, success({ platforms: activeService.platforms() }));
      }
      if (req.method === "GET" && req.url === "/v1/capabilities") {
        authorize(req, token);
        return json(res, 200, success(activeService.capabilities()));
      }
      if (req.method === "POST" && (req.url === "/v1/login" || req.url === "/v1/login/bounded")) {
        authorize(req, token);
        const request = await readJSON(req);
        if (req.url === "/v1/login/bounded" && !request.budget) {
          throw new ServiceError("invalid_budget", "bounded login requires a budget", 400);
        }
        const { status, result } = await activeService.login(request, controller.signal);
        return json(res, status, success(result));
      }
      if (req.method === "POST" && req.url === "/v1/profiles/prewarm") {
        authorize(req, token);
        return json(res, 200, success(await activeService.prewarm(await readJSON(req), controller.signal)));
      }
      if (req.method === "POST" && req.url === "/v1/challenges/status") {
        authorize(req, token);
        return json(res, 200, success(activeService.challengeStatus(await readJSON(req))));
      }
      if (req.method === "POST" && req.url === "/v1/challenges/cancel") {
        authorize(req, token);
        return json(res, 200, success(await activeService.cancelChallenge(await readJSON(req))));
      }
      const profile = req.method === "DELETE" ? profileDeleteParameters(req.url) : undefined;
      if (profile) {
        authorize(req, token);
        return json(res, 200, success(await activeService.erase(profile)));
      }
      if (req.method === "DELETE" && req.url === "/v1/profiles") {
        authorize(req, token);
        return json(res, 200, success(await activeService.erase(await readJSON(req))));
      }
      return json(res, 404, failure("not_found", "route not found"));
    } catch (error) {
      const known = error instanceof ServiceError;
      const status = known ? error.status : 500;
      if (!known) {
        console.error(JSON.stringify({
          event: "unhandled_login_error",
          name: error?.name,
          code: error?.code,
        }));
      }
      if (!res.destroyed && !res.headersSent) {
        json(res, status, failure(
          known ? error.code : "internal_error",
          known ? error.message : "internal server error",
          known ? error.details : undefined,
        ), {
          ...(status === 429 ? { "retry-after": "5" } : {}),
          ...(status === 401 ? { "www-authenticate": "Bearer" } : {}),
        });
      }
    }
  });
}

const server = createServer();
async function shutdown() {
  const timeoutMs = Number.parseInt(process.env.SOCIAL_LOGIN_SHUTDOWN_TIMEOUT_MS || "30000", 10);
  server.closeIdleConnections?.();
  const closed = new Promise((resolve) => server.close(resolve));
  await Promise.allSettled([
    service.shutdown(timeoutMs),
    Promise.race([closed, new Promise((resolve) => setTimeout(resolve, timeoutMs))]),
  ]);
  server.closeAllConnections?.();
  process.exitCode = 0;
  setTimeout(() => process.exit(0), 50).unref();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.SOCIAL_LOGIN_MANAGED === "1") {
    process.stdin.resume();
    process.stdin.once("end", () => void shutdown());
  }
  process.once("SIGTERM", () => void shutdown());
  process.once("SIGINT", () => void shutdown());
  server.listen(PORT, process.env.HOST || "0.0.0.0", () => console.log(JSON.stringify({ event: "listening", port: PORT })));
}
