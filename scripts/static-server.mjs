/**
 * Combined static file server + reverse proxy.
 *
 * Replaces `sirv-cli` for the static launcher. The reason a plain static
 * server is not enough: Vite's dev server (used by `npm run dev`) configures
 * a proxy for `/api`, `/sockets`, `/server_info`, `/alive`, `/health`,
 * `/ready`, `/docs`, `/redoc`, `/openapi.json` (see vite.config.ts) so
 * requests to those paths are forwarded to
 * the agent-server even when the browser is hitting Vite directly on :3001.
 * sirv-cli has no proxy support, so under `--single` it falls back to
 * index.html for any of those paths — making `/server_info` look like HTML
 * to the SPA when the user hits the static port directly (e.g. via a tunnel
 * that exposes :3001).
 *
 * This script provides Vite-equivalent behaviour: serve static files from
 * --dir, fall back to index.html for HTML navigations, and reverse-proxy
 * configured prefixes to upstream backends. The proxy + WebSocket logic is
 * deliberately kept identical in spirit to scripts/ingress.mjs so the two
 * servers route the same way.
 *
 * Usage (mirrors scripts/ingress.mjs's --route flag style):
 *   node scripts/static-server.mjs \
 *     --port 3001 --dir build \
 *     --route "/api/automation=http://localhost:18001" \
 *     --route "/api=http://localhost:18000" \
 *     --route "/server_info=http://localhost:18000" \
 *     --route "/sockets=http://localhost:18000"
 */

import { createPublicKey, createVerify } from "node:crypto";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import sirv from "sirv";

import {
  createProxyHandlers,
  createRouter,
  matchesPathPrefix,
} from "./proxy-utils.mjs";

const DEFAULT_CLERK_SIGN_IN_PATH = "/__clerk/sign-in";
const DEFAULT_CLERK_PUBLIC_PATHS = [
  DEFAULT_CLERK_SIGN_IN_PATH,
  "/alive",
  "/health",
  "/ready",
  "/favicon.ico",
  "/robots.txt",
];
const DEFAULT_CLERK_JWKS_URL = "https://api.clerk.com/v1/jwks";
const CLERK_JWKS_CACHE_MS = 5 * 60 * 1000;

// ─────────────────────────────────────────────────────────────────────────────
// SPA fallback helpers
// ─────────────────────────────────────────────────────────────────────────────

const ASSET_LIKE_EXTENSIONS = new Set([
  ".br",
  ".css",
  ".gif",
  ".gz",
  ".html",
  ".htm",
  ".ico",
  ".jpeg",
  ".jpg",
  ".js",
  ".json",
  ".map",
  ".mjs",
  ".mp3",
  ".png",
  ".svg",
  ".ttf",
  ".txt",
  ".wav",
  ".webmanifest",
  ".webp",
  ".woff",
  ".woff2",
  ".xml",
]);

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

export function parseArgs(argv = process.argv.slice(2)) {
  const config = {
    port: 3001,
    host: "::",
    dir: "build",
    routes: {},
    rejectPrefixes: [],
    sessionApiKey: null,
    authRequired: false,
    runtimeServicesInfo: null,
    lockToCloud: null,
    basePath: "/",
    clerkAuth: readClerkAuthConfigFromEnv(),
  };

  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    switch (flag) {
      case "-p":
      case "--port":
        config.port = Number.parseInt(argv[++i], 10);
        break;
      case "-H":
      case "--host":
        config.host = argv[++i];
        break;
      case "-d":
      case "--dir":
        config.dir = argv[++i];
        break;
      case "-r":
      case "--route": {
        const value = argv[++i];
        const eq = value.indexOf("=");
        if (eq < 0) {
          throw new Error(`Invalid --route (expected /prefix=url): ${value}`);
        }
        const prefix = value.slice(0, eq);
        const url = value.slice(eq + 1);
        if (!prefix.startsWith("/")) {
          throw new Error(`--route prefix must start with '/': ${prefix}`);
        }
        config.routes[prefix] = url;
        break;
      }
      case "--session-api-key":
        config.sessionApiKey = argv[++i] || null;
        break;
      case "--runtime-services-info":
        config.runtimeServicesInfo = argv[++i] || null;
        break;
      case "--lock-to-cloud":
        config.lockToCloud = argv[++i] || null;
        break;
      case "--base-path":
        config.basePath = normalizeBasePath(argv[++i]);
        break;
      case "--clerk-auth":
        config.clerkAuth.enabled = true;
        break;

      case "--auth-required":
        config.authRequired = true;
        break;
      case "--reject-prefix": {
        const prefix = argv[++i];
        if (!prefix?.startsWith("/")) {
          throw new Error(
            `--reject-prefix value must start with '/': ${prefix ?? "(empty)"}`,
          );
        }
        config.rejectPrefixes.push(prefix);
        break;
      }
      case "-h":
      case "--help":
        showHelp();
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown flag: ${flag}`);
    }
  }

  // Guard: --session-api-key and --auth-required are semantically
  // mutually exclusive. The first auto-injects the key (local mode);
  // the second forces the user to paste it (public mode). Combining
  // both is a misconfiguration.
  if (config.sessionApiKey && config.authRequired) {
    console.error(
      "ERROR: --session-api-key and --auth-required are mutually exclusive.\n" +
        "  Use --session-api-key for local mode (key auto-injected).\n" +
        "  Use --auth-required for public mode (user pastes key).",
    );
    process.exit(1);
  }

  return config;
}

function parseBooleanEnv(value) {
  if (value == null || value === "") return false;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function parseCsvEnv(value) {
  return (value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function normalizeMultilineSecret(value) {
  return value ? value.replaceAll("\\n", "\n") : null;
}

function readClerkAuthConfigFromEnv(env = process.env) {
  const enabled = parseBooleanEnv(env.CLERK_AUTH_ENABLED);
  return {
    enabled,
    publishableKey: env.CLERK_PUBLISHABLE_KEY || null,
    jwtKey: normalizeMultilineSecret(
      env.CLERK_JWT_KEY || env.CLERK_PEM_PUBLIC_KEY || null,
    ),
    secretKey: env.CLERK_SECRET_KEY || null,
    jwksUrl: env.CLERK_JWKS_URL || DEFAULT_CLERK_JWKS_URL,
    authorizedParties: parseCsvEnv(
      env.CLERK_AUTHORIZED_PARTIES || env.CLERK_ALLOWED_ORIGINS,
    ),
    allowedUserIds: parseCsvEnv(env.CLERK_ALLOWED_USER_IDS),
    allowedEmails: parseCsvEnv(env.CLERK_ALLOWED_EMAILS).map((email) =>
      email.toLowerCase(),
    ),
    signInPath: normalizePathEnv(
      env.CLERK_SIGN_IN_PATH,
      DEFAULT_CLERK_SIGN_IN_PATH,
    ),
    publicPaths: [
      ...DEFAULT_CLERK_PUBLIC_PATHS,
      ...parseCsvEnv(env.CLERK_AUTH_PUBLIC_PATHS),
    ],
  };
}

function normalizePathEnv(value, fallback) {
  if (!value) return fallback;
  return value.startsWith("/") ? value : `/${value}`;
}

function normalizeBasePath(value) {
  const raw = (value ?? "").trim();
  if (!raw || raw === "/") return "/";

  const withLeadingSlash = raw.startsWith("/") ? raw : `/${raw}`;
  return withLeadingSlash.replace(/\/+$/, "");
}

function showHelp() {
  console.log(`
Combined static file server + reverse proxy.

USAGE:
  node scripts/static-server.mjs [options]

OPTIONS:
  -p, --port  <port>           Port to bind (default: 3001)
  -H, --host  <host>           Hostname to bind (default: :: dual-stack)
  -d, --dir   <dir>            Directory to serve (default: build)
  -r, --route <prefix=url>     Proxy <prefix> (and subpaths) to <url>;
                               may be repeated. WebSockets supported.
  --session-api-key <key>      Inject session API key into index.html so the
                               pre-built frontend authenticates to agent-server
                               without needing VITE_SESSION_API_KEY baked in.
  --auth-required              Inject authRequired flag into index.html so the
                               pre-built frontend shows the API key entry screen
                               (public mode) without VITE_AUTH_REQUIRED baked in.
  --runtime-services-info <json>
                               Inject a JSON description of the local runtime
                               services into index.html so the pre-built
                               frontend can populate the agent's
                               <RUNTIME_SERVICES> system-prompt block without
                               VITE_RUNTIME_SERVICES_INFO baked in.
  --lock-to-cloud <cloud-url>  Lock backend setup to a single OpenHands Cloud
                               URL. Hides manual/local backend setup and the
                               custom Cloud URL field in the pre-built frontend.
  --base-path <path>           Mount the SPA under <path> (default: /).
                               For example, --base-path /canvas serves
                               index.html and assets under /canvas.
  --clerk-auth                 Enable the Clerk server-side gate. Intended for
                               runtime use with CLERK_AUTH_ENABLED=true,
                               CLERK_PUBLISHABLE_KEY, and CLERK_JWT_KEY (or
                               CLERK_SECRET_KEY / CLERK_JWKS_URL).
  --reject-prefix <prefix>     Return 503 for requests matching <prefix>
                               instead of SPA-fallbacking to index.html;
                               may be repeated. Useful in --frontend-only
                               mode to cleanly reject API paths.
  -h, --help                   Show this help

ROUTING:
  • Routes are matched by longest prefix first (most-specific wins).
  • Reject prefixes are checked before SPA fallback — matching requests
    get 503 immediately.
  • Anything that does not match a route or reject prefix is served
    from --dir.
  • Unknown paths fall back to index.html (SPA mode), unless they look
    like an asset request (have a known file extension), in which case
    a 404 is returned.
`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Clerk auth gate
// ─────────────────────────────────────────────────────────────────────────────

function isClerkAuthEnabled(config) {
  return Boolean(config?.enabled);
}

function getClerkConfigError(config) {
  if (!isClerkAuthEnabled(config)) return null;
  if (!config.publishableKey) return "CLERK_PUBLISHABLE_KEY is required";
  const hasCustomJwksUrl =
    config.jwksUrl && config.jwksUrl !== DEFAULT_CLERK_JWKS_URL;
  if (!config.jwtKey && !config.secretKey && !hasCustomJwksUrl) {
    return "CLERK_JWT_KEY, CLERK_SECRET_KEY, or CLERK_JWKS_URL is required";
  }
  return null;
}

function parseCookies(cookieHeader = "") {
  const cookies = new Map();
  for (const pair of cookieHeader.split(";")) {
    const index = pair.indexOf("=");
    if (index < 0) continue;
    const name = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (name) cookies.set(name, decodeURIComponent(value));
  }
  return cookies;
}

function getSessionToken(req) {
  const authorization = req.headers.authorization;
  if (authorization?.toLowerCase().startsWith("bearer ")) {
    return authorization.slice("bearer ".length).trim();
  }
  return parseCookies(req.headers.cookie).get("__session") ?? null;
}

function base64UrlDecode(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "=",
  );
  return Buffer.from(padded, "base64");
}

function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(base64UrlDecode(encodedHeader).toString("utf8"));
  const payload = JSON.parse(base64UrlDecode(encodedPayload).toString("utf8"));
  return {
    header,
    payload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: base64UrlDecode(encodedSignature),
  };
}

function getRequestOrigin(req) {
  const protoHeader = req.headers["x-forwarded-proto"];
  const hostHeader = req.headers["x-forwarded-host"] ?? req.headers.host;
  const proto = Array.isArray(protoHeader)
    ? protoHeader[0]
    : protoHeader || "http";
  const host = Array.isArray(hostHeader) ? hostHeader[0] : hostHeader;
  return host ? `${proto}://${host}` : null;
}

function isHtmlNavigation(req) {
  const method = req.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") return false;
  const accept = req.headers.accept ?? "";
  return accept.includes("text/html");
}

function isPublicClerkPath(urlPath, config) {
  return (config.publicPaths ?? DEFAULT_CLERK_PUBLIC_PATHS).some((prefix) =>
    matchesPathPrefix(urlPath, prefix),
  );
}

function writeAuthConfigError(res, message) {
  res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(`Clerk auth is misconfigured: ${message}`);
}

function writeUnauthorized(req, res, config) {
  if (isHtmlNavigation(req)) {
    const origin = getRequestOrigin(req) ?? "";
    const redirectUrl = `${origin}${req.url ?? "/"}`;
    const location =
      `${config.signInPath ?? DEFAULT_CLERK_SIGN_IN_PATH}` +
      `?redirect_url=${encodeURIComponent(redirectUrl)}`;
    res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
    res.end();
    return;
  }

  res.writeHead(401, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify({ error: "Authentication required" }));
}

function writeUnauthorizedSocket(socket) {
  socket.write(
    "HTTP/1.1 401 Unauthorized\r\n" +
      "Connection: close\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "\r\n" +
      "Authentication required",
  );
  socket.destroy();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function serveClerkSignInPage(req, res, config) {
  const origin = getRequestOrigin(req) ?? "";
  const currentUrl = new URL(req.url ?? "/", origin || "http://localhost");
  const redirectUrl = currentUrl.searchParams.get("redirect_url") || "/";
  const publishableKey = escapeHtml(config.publishableKey);
  const safeRedirectUrl = escapeHtml(redirectUrl);
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <script async crossorigin="anonymous" data-clerk-publishable-key="${publishableKey}" src="https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js"></script>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b0f19; color: #f8fafc; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { width: min(440px, calc(100vw - 32px)); }
    h1 { margin: 0 0 16px; font-size: 1.5rem; text-align: center; }
    p { margin: 0 0 24px; color: #cbd5e1; text-align: center; }
  </style>
</head>
<body>
  <main>
    <h1>Sign in to Agent Canvas</h1>
    <p>Use your approved Google account to continue.</p>
    <div id="clerk-sign-in"></div>
  </main>
  <script>
    (async function () {
      var redirectUrl = "${safeRedirectUrl}";
      function fail(error) {
        document.getElementById("clerk-sign-in").textContent =
          "Unable to load Clerk sign-in. Check the Clerk publishable key and allowed origins.";
        console.error(error);
      }
      try {
        await window.Clerk.load();
        if (window.Clerk.user) {
          window.location.assign(redirectUrl);
          return;
        }
        window.Clerk.mountSignIn(document.getElementById("clerk-sign-in"), {
          fallbackRedirectUrl: redirectUrl,
          forceRedirectUrl: redirectUrl,
          signUpFallbackRedirectUrl: redirectUrl,
          signUpForceRedirectUrl: redirectUrl
        });
      } catch (error) {
        fail(error);
      }
    }());
  </script>
</body>
</html>`;

  const buf = Buffer.from(html, "utf8");
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": buf.length,
    "Cache-Control": "no-store",
  });
  if (req.method === "HEAD") {
    res.end();
  } else {
    res.end(buf);
  }
}

function createClerkKeyResolver(config) {
  let cachedJwks = null;
  let cachedAt = 0;

  async function fetchJwks() {
    const now = Date.now();
    if (cachedJwks && now - cachedAt < CLERK_JWKS_CACHE_MS) {
      return cachedJwks;
    }

    const headers = config.secretKey
      ? { Authorization: `Bearer ${config.secretKey}` }
      : {};
    const response = await fetch(config.jwksUrl || DEFAULT_CLERK_JWKS_URL, {
      headers,
    });
    if (!response.ok) {
      throw new Error(`Unable to fetch Clerk JWKS (${response.status})`);
    }
    cachedJwks = await response.json();
    cachedAt = now;
    return cachedJwks;
  }

  return async function resolvePublicKey(kid) {
    if (config.jwtKey) return createPublicKey(config.jwtKey);

    const jwks = await fetchJwks();
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const key = keys.find((candidate) => !kid || candidate.kid === kid);
    if (!key) throw new Error("No matching Clerk JWKS key");
    return createPublicKey({ key, format: "jwk" });
  };
}

function verifyJwtSignature(signingInput, signature, publicKey) {
  const verifier = createVerify("RSA-SHA256");
  verifier.update(signingInput);
  verifier.end();
  return verifier.verify(publicKey, signature);
}

function verifyJwtClaims(payload, req, config) {
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Clerk session token expired");
  }
  if (typeof payload.nbf === "number" && payload.nbf > now) {
    throw new Error("Clerk session token not active yet");
  }

  const requestOrigin = getRequestOrigin(req);
  const authorizedParties =
    config.authorizedParties?.length > 0
      ? config.authorizedParties
      : requestOrigin
        ? [requestOrigin]
        : [];
  if (
    authorizedParties.length > 0 &&
    typeof payload.azp === "string" &&
    !authorizedParties.includes(payload.azp)
  ) {
    throw new Error("Clerk session token authorized party mismatch");
  }

  if (
    config.allowedUserIds?.length > 0 &&
    !config.allowedUserIds.includes(payload.sub)
  ) {
    throw new Error("Clerk session user is not allowed");
  }

  if (config.allowedEmails?.length > 0) {
    const emailClaims = [
      payload.email,
      payload.email_address,
      payload.primary_email_address,
    ].filter((value) => typeof value === "string");
    const normalizedEmails = emailClaims.map((email) => email.toLowerCase());
    if (
      normalizedEmails.length === 0 ||
      !normalizedEmails.some((email) => config.allowedEmails.includes(email))
    ) {
      throw new Error("Clerk session email is not allowed");
    }
  }
}

function createClerkAuthenticator(config) {
  const resolvePublicKey = createClerkKeyResolver(config);

  return async function authenticateClerkRequest(req) {
    const token = getSessionToken(req);
    if (!token) return false;

    const { header, payload, signingInput, signature } = parseJwt(token);
    if (header.alg !== "RS256") {
      throw new Error("Unsupported Clerk JWT algorithm");
    }

    const publicKey = await resolvePublicKey(header.kid);
    if (!verifyJwtSignature(signingInput, signature, publicKey)) {
      throw new Error("Invalid Clerk session token signature");
    }

    verifyJwtClaims(payload, req, config);
    return true;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime config injection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a tiny inline script that seeds runtime config into the page.
 *
 * - `sessionApiKey`: exposed to the app two ways so a fresh-localStorage
 *   browser can authenticate even though the published bundle has no
 *   VITE_SESSION_API_KEY baked in:
 *     1. `window.__AGENT_CANVAS_SESSION_API_KEY__` — read by
 *        `getBakedSessionApiKey()` in `agent-server-config.ts` as a fallback
 *        when the env var is empty. This is symmetric with how
 *        `__AGENT_CANVAS_AUTH_REQUIRED__` works for the auth-required flag.
 *     2. Written to `openhands-agent-server-config.sessionApiKey` in
 *        localStorage for compatibility with the legacy storage key. Useful
 *        for any code path that still reads it (e.g. e2e test fixtures).
 *        Always overwrites when the stored value differs so a rotated key
 *        is not shadowed by a stale one.
 *
 * - `authRequired`: sets `window.__AGENT_CANVAS_AUTH_REQUIRED__ = true` so the
 *   pre-built frontend shows the API key entry screen (public mode) without
 *   VITE_AUTH_REQUIRED baked in.
 *
 * - `runtimeServicesInfo`: a JSON string describing the local services
 *   (agent-server, automation, …), exposed as
 *   `window.__AGENT_CANVAS_RUNTIME_SERVICES_INFO__`. Read by
 *   `parseRuntimeServicesInfo()` in `agent-server-adapter.ts` as a fallback
 *   when `VITE_RUNTIME_SERVICES_INFO` is empty, so static builds (Docker /
 *   published binary) still populate the agent's `<RUNTIME_SERVICES>` block.
 *
 * - `lockToCloud`: an OpenHands Cloud URL exposed as
 *   `window.__AGENT_CANVAS_LOCK_TO_CLOUD__`. Read by `getLockedCloudHost()` in
 *   `agent-server-config.ts` so pre-built frontend bundles can hide manual
 *   backend setup and the custom Cloud URL field at runtime.
 *
 * - `basePath`: the path prefix the SPA is mounted under, exposed as
 *   `window.__AGENT_CANVAS_BASE_PATH__` so runtime static assets like locale
 *   files can resolve through the same subpath as the built bundle.
 */
function makeConfigInjectionScript(
  sessionApiKey,
  authRequired,
  runtimeServicesInfo,
  lockToCloud,
  basePath,
) {
  const parts = [];

  if (sessionApiKey) {
    const keyLiteral = JSON.stringify(sessionApiKey);
    // Window global — read at module init by getBakedSessionApiKey().
    // Set first so it's available even if the localStorage write throws.
    parts.push(`window.__AGENT_CANVAS_SESSION_API_KEY__=${keyLiteral};`);
    // Always overwrite when the stored key differs from the runtime key.
    // A previous session may have persisted a now-stale key; the runtime
    // value (from --session-api-key) is the server's truth.
    parts.push(
      `try{` +
        `var _k='openhands-agent-server-config',` +
        `_c=JSON.parse(localStorage.getItem(_k)||'{}');` +
        `if(_c.sessionApiKey!==${keyLiteral}){` +
        `_c.sessionApiKey=${keyLiteral};` +
        `localStorage.setItem(_k,JSON.stringify(_c));` +
        `}` +
        `}catch(e){}`,
    );
  }

  if (authRequired) {
    parts.push(`window.__AGENT_CANVAS_AUTH_REQUIRED__=true;`);
  }

  if (runtimeServicesInfo) {
    // Stored as the raw JSON string so the browser-side parser
    // (parseRuntimeServicesInfo) can JSON.parse it exactly like the
    // VITE_RUNTIME_SERVICES_INFO env var. JSON.stringify produces a safe JS
    // string literal for the inline <script>.
    parts.push(
      `window.__AGENT_CANVAS_RUNTIME_SERVICES_INFO__=${JSON.stringify(runtimeServicesInfo)};`,
    );
  }

  if (lockToCloud) {
    parts.push(
      `window.__AGENT_CANVAS_LOCK_TO_CLOUD__=${JSON.stringify(lockToCloud)};`,
    );
  }

  if (basePath && basePath !== "/") {
    parts.push(
      `window.__AGENT_CANVAS_BASE_PATH__=${JSON.stringify(basePath)};`,
    );
  }

  if (parts.length === 0) return "";

  return `<script>(function(){${parts.join("")}}());</script>`;
}

/**
 * Serve index.html with runtime config injected into <head>.
 * Returns true if the response was written, false if the file was not found.
 */
async function serveInjectedIndexHtml(
  req,
  res,
  indexPath,
  {
    sessionApiKey,
    authRequired,
    runtimeServicesInfo,
    lockToCloud,
    basePath,
  } = {},
) {
  let content;
  try {
    content = await readFile(indexPath, "utf8");
  } catch {
    return false;
  }

  const script = makeConfigInjectionScript(
    sessionApiKey,
    authRequired,
    runtimeServicesInfo,
    lockToCloud,
    basePath,
  );
  // Inject right before </head> so the key is available before any app code runs.
  // replace() targets the first (and only) </head> in well-formed HTML.
  const injected = content.includes("</head>")
    ? content.replace("</head>", `${script}\n</head>`)
    : content.includes("</body>")
      ? content.replace("</body>", `${script}\n</body>`)
      : script + content;

  const buf = Buffer.from(injected, "utf8");
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": buf.length,
    "Cache-Control": "no-cache",
  });
  if (req.method === "HEAD") {
    res.end();
  } else {
    res.end(buf);
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static file serving
// ─────────────────────────────────────────────────────────────────────────────

function parseUrlPath(req, res) {
  const rawPath = (req.url ?? "/").split("?")[0];
  try {
    return decodeURIComponent(rawPath);
  } catch {
    res.writeHead(400);
    res.end("Bad Request");
    return null;
  }
}

function isGetOrHead(req) {
  return req.method === "GET" || req.method === "HEAD";
}

function needsRuntimeInjection(injectionOpts) {
  return Boolean(
    injectionOpts.sessionApiKey ||
    injectionOpts.authRequired ||
    injectionOpts.runtimeServicesInfo ||
    injectionOpts.lockToCloud ||
    (injectionOpts.basePath && injectionOpts.basePath !== "/"),
  );
}

function looksLikeAssetRequest(urlPath) {
  const last = urlPath.split("/").pop() ?? "";
  return ASSET_LIKE_EXTENSIONS.has(extname(last).toLowerCase());
}

function matchesAnyPrefix(urlPath, prefixes) {
  return prefixes.some((prefix) => matchesPathPrefix(urlPath, prefix));
}

function rejectUnavailable(res) {
  res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Service Unavailable (no backend configured for this route)");
}

function notFound(res) {
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not Found");
}

function isMountedPath(urlPath, basePath) {
  return (
    basePath === "/" ||
    urlPath === basePath ||
    urlPath.startsWith(`${basePath}/`)
  );
}

function stripBasePathFromUrl(rawUrl, basePath) {
  if (basePath === "/") return rawUrl;

  const [rawPath = "/", ...rest] = (rawUrl || "/").split("?");
  const suffix = rawPath.slice(basePath.length) || "/";
  const path = suffix.startsWith("/") ? suffix : `/${suffix}`;
  return rest.length > 0 ? `${path}?${rest.join("?")}` : path;
}

function redirectToMountedPath(req, res, urlPath, basePath) {
  if (basePath === "/" || !isGetOrHead(req) || looksLikeAssetRequest(urlPath)) {
    return false;
  }

  const [, query = ""] = (req.url ?? "/").split("?", 2);
  const path = urlPath === "/" ? "/" : urlPath;
  const location = `${basePath}${path}${query ? `?${query}` : ""}`;
  res.writeHead(308, { Location: location });
  res.end();
  return true;
}

function setStaticHeaders(res, pathname) {
  const extension = extname(pathname).toLowerCase();
  if (extension === ".js" || extension === ".mjs") {
    res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  }

  if (pathname.startsWith("/assets/")) {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    return;
  }
  res.setHeader("Cache-Control", "no-cache");
}

function createStaticMiddleware(dirAbs) {
  return sirv(dirAbs, {
    etag: true,
    single: false,
    setHeaders: setStaticHeaders,
  });
}

async function handleStatic(
  req,
  res,
  dirAbs,
  staticMiddleware,
  injectionOpts = {},
  rejectPrefixes = [],
  basePath = "/",
) {
  const urlPath = parseUrlPath(req, res);
  if (urlPath === null) return;

  if (!isMountedPath(urlPath, basePath)) {
    if (matchesAnyPrefix(urlPath, rejectPrefixes)) {
      rejectUnavailable(res);
      return;
    }
    if (!redirectToMountedPath(req, res, urlPath, basePath)) notFound(res);
    return;
  }

  const mountedUrl = stripBasePathFromUrl(req.url ?? "/", basePath);
  const mountedPath = parseUrlPath({ ...req, url: mountedUrl }, res);
  if (mountedPath === null) return;

  const injectRuntimeConfig = needsRuntimeInjection(injectionOpts);
  const indexPath = resolve(dirAbs, "index.html");

  if (
    injectRuntimeConfig &&
    isGetOrHead(req) &&
    (mountedPath === "/" || mountedPath === "/index.html")
  ) {
    if (await serveInjectedIndexHtml(req, res, indexPath, injectionOpts))
      return;
  }

  const mountedReq = Object.create(req);
  mountedReq.url = mountedUrl;

  staticMiddleware(mountedReq, res, async () => {
    if (matchesAnyPrefix(mountedPath, rejectPrefixes)) {
      rejectUnavailable(res);
      return;
    }

    if (isGetOrHead(req) && !looksLikeAssetRequest(mountedPath)) {
      if (await serveInjectedIndexHtml(req, res, indexPath, injectionOpts)) {
        return;
      }
    }

    notFound(res);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

export function startStaticServer(config) {
  const route = createRouter(config.routes);
  const proxy = createProxyHandlers({ label: `static:${config.port}` });
  const dirAbs = resolve(config.dir);
  const clerkAuth = config.clerkAuth ?? { enabled: false };
  const clerkConfigError = getClerkConfigError(clerkAuth);
  const authenticateClerkRequest = isClerkAuthEnabled(clerkAuth)
    ? createClerkAuthenticator(clerkAuth)
    : null;
  const injectionOpts = {
    sessionApiKey: config.sessionApiKey || null,
    authRequired: config.authRequired || false,
    runtimeServicesInfo: config.runtimeServicesInfo || null,
    lockToCloud: config.lockToCloud || null,
    basePath: normalizeBasePath(config.basePath),
  };
  const basePath = injectionOpts.basePath;
  const rejectPrefixes = config.rejectPrefixes ?? [];
  const staticMiddleware = createStaticMiddleware(dirAbs);

  const uninstallDiagnostics = proxy.installDiagnostics();

  const server = createServer((req, res) => {
    (async () => {
      const urlPath = parseUrlPath(req, res);
      if (urlPath === null) return;

      if (
        isClerkAuthEnabled(clerkAuth) &&
        urlPath === (clerkAuth.signInPath ?? DEFAULT_CLERK_SIGN_IN_PATH)
      ) {
        if (clerkConfigError) {
          writeAuthConfigError(res, clerkConfigError);
          return;
        }
        serveClerkSignInPage(req, res, clerkAuth);
        return;
      }

      if (
        isClerkAuthEnabled(clerkAuth) &&
        !isPublicClerkPath(urlPath, clerkAuth)
      ) {
        if (clerkConfigError) {
          writeAuthConfigError(res, clerkConfigError);
          return;
        }
        try {
          if (!(await authenticateClerkRequest(req))) {
            writeUnauthorized(req, res, clerkAuth);
            return;
          }
        } catch (err) {
          console.warn(
            `Clerk auth rejected ${req.method ?? "GET"} ${req.url}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
          writeUnauthorized(req, res, clerkAuth);
          return;
        }
      }

      const backend = route(req.url ?? "/");
      if (backend) {
        proxy.proxyHttp(req, res, backend);
        return;
      }
      await handleStatic(
        req,
        res,
        dirAbs,
        staticMiddleware,
        injectionOpts,
        rejectPrefixes,
        basePath,
      );
    })().catch((err) => {
      console.error(`Static handler error for ${req.url}:`, err);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end("Internal Server Error");
      }
    });
  });

  server.on("upgrade", (req, socket, head) => {
    (async () => {
      const urlPath = (() => {
        try {
          return decodeURIComponent((req.url ?? "/").split("?")[0]);
        } catch {
          return null;
        }
      })();
      if (urlPath === null) {
        socket.destroy();
        return;
      }

      if (
        isClerkAuthEnabled(clerkAuth) &&
        !isPublicClerkPath(urlPath, clerkAuth)
      ) {
        if (clerkConfigError) {
          socket.write(
            "HTTP/1.1 503 Service Unavailable\r\n" +
              "Connection: close\r\n" +
              "Content-Type: text/plain; charset=utf-8\r\n" +
              "\r\n" +
              `Clerk auth is misconfigured: ${clerkConfigError}`,
          );
          socket.destroy();
          return;
        }
        try {
          if (!(await authenticateClerkRequest(req))) {
            writeUnauthorizedSocket(socket);
            return;
          }
        } catch (err) {
          console.warn(
            `Clerk auth rejected websocket ${req.url}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
          writeUnauthorizedSocket(socket);
          return;
        }
      }

      const backend = route(req.url ?? "/");
      if (backend) {
        proxy.proxyWebSocket(req, socket, head, backend);
        return;
      }
      socket.destroy();
    })().catch((err) => {
      console.error(`Static websocket handler error for ${req.url}:`, err);
      socket.destroy();
    });
  });
  server.on("close", uninstallDiagnostics);

  return new Promise((resolveListen) => {
    server.listen(config.port, config.host, () => {
      const displayPath = basePath === "/" ? "/" : `${basePath}/`;
      console.log("");
      console.log(
        `Static-server + proxy listening on http://${config.host}:${config.port}${displayPath}`,
      );
      console.log(`  Static dir: ${dirAbs}`);
      console.log(`  Base path: ${basePath}`);
      const sortedRoutes = Object.entries(config.routes).sort(
        ([a], [b]) => b.length - a.length,
      );
      for (const [prefix, backend] of sortedRoutes) {
        console.log(`  ${prefix} -> ${backend}`);
      }
      if (rejectPrefixes.length > 0) {
        for (const prefix of rejectPrefixes) {
          console.log(`  ${prefix} -> 503 (rejected)`);
        }
      }
      if (config.lockToCloud) {
        console.log(`  Backend setup locked to Cloud: ${config.lockToCloud}`);
      }
      if (isClerkAuthEnabled(clerkAuth)) {
        console.log(
          `  Clerk auth: enabled (${clerkAuth.signInPath ?? DEFAULT_CLERK_SIGN_IN_PATH})`,
        );
      }
      console.log("  * (default) -> static files + SPA fallback");
      console.log("");
      resolveListen(server);
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

const isMainModule =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  try {
    const config = parseArgs();
    await startStaticServer(config);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }
}
