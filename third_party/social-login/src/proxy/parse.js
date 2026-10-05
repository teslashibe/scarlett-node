import { ServiceError } from "../http/errors.js";

export function parseProxyURL(raw) {
  if (!raw) return undefined;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ServiceError("invalid_proxy", "proxy_url is invalid", 400);
  }
  if (!["http:", "https:", "socks5:"].includes(url.protocol)) {
    throw new ServiceError("invalid_proxy", "proxy_url scheme is unsupported", 400);
  }
  if (!url.hostname) throw new ServiceError("invalid_proxy", "proxy_url host is required", 400);
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new ServiceError("invalid_proxy", "proxy_url must not contain a path, query, or fragment", 400);
  }
  const defaultPort = url.protocol === "https:" ? "443" : url.protocol === "socks5:" ? "1080" : "80";
  return {
    url: url.href,
    server: `${url.protocol}//${url.hostname}:${url.port || defaultPort}`,
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
  };
}
