// "Sign in with Sharpnr" for a browser app: Authorization Code + PKCE.
//
// This app is a *public* client. Its code runs in the user's browser, so it
// has no client secret; PKCE proves that whoever redeems the code is whoever
// started the login. No library is used, so every step is visible:
//
//   startLogin()      discovery → PKCE verifier/challenge, state, nonce
//                     → redirect to /oauth/authorize
//   startPopupLogin() the same, in a small window instead (like Google)
//   completeLogin()   (back on /callback) check state and iss
//                     → POST /oauth/token with the code and verifier
//                     → verify the ID token signature with the JWKS
//   fetchUserInfo()   GET /oauth/userinfo with the access token
//   refresh()         POST /oauth/token with the refresh token (rotation)
//   revoke()          POST /oauth/revoke
//
// Tokens are kept in sessionStorage so a page reload keeps you signed in
// while testing. A production app would keep them in memory, or better,
// let its own backend hold them.

const SETTINGS_KEY = "sharp-test-client:settings";
const PENDING_KEY = "sharp-test-client:pending";
const SESSION_KEY = "sharp-test-client:session";

export const redirectUri = `${window.location.origin}/callback`;

// ---------------------------------------------------------------------------
// Settings (issuer, client_id, scope)
// ---------------------------------------------------------------------------

export function loadSettings() {
  const defaults = {
    issuer: import.meta.env.VITE_SHARP_ISSUER || "http://localhost:3000",
    clientId: import.meta.env.VITE_SHARP_CLIENT_ID || "",
    scope:
      import.meta.env.VITE_SHARP_SCOPE || "openid profile email offline_access",
  };
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(SETTINGS_KEY)) };
  } catch {
    return defaults;
  }
}

export function saveSettings(settings) {
  const cleaned = { ...settings, issuer: settings.issuer.replace(/\/+$/, "") };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(cleaned));
  return cleaned;
}

// ---------------------------------------------------------------------------
// Session (tokens + verified claims)
// ---------------------------------------------------------------------------

export function loadSession() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY));
  } catch {
    return null;
  }
}

export function saveSession(session) {
  if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  else sessionStorage.removeItem(SESSION_KEY);
}

// ---------------------------------------------------------------------------
// Step 1: send the user to Sharpnr (whole page, or a popup)
// ---------------------------------------------------------------------------

/** Full-page redirect: this tab goes to Sharpnr and comes back on /callback. */
export async function startLogin(settings, { prompt, log }) {
  const url = await authorizeUrl(settings, { prompt, log });
  log(`Redirecting to ${url.origin}${url.pathname} (PKCE S256, state, nonce)`);
  window.location.assign(url);
}

const POPUP_NAME = "sharp-signin";
const POPUP_MESSAGE = "sharp-oauth-callback";
// Prefixed to `state` so the page landing on /callback knows it is the popup.
// `state` always comes back unchanged, unlike `window.name`, which browsers
// may clear when the popup navigates to another site and back.
const POPUP_STATE_PREFIX = "popup.";

/**
 * Popup sign-in: Sharpnr opens in a small window, this page stays put.
 *
 *   this page                         popup
 *   ─────────                         ─────
 *   window.open() ──────────────────▶ /oauth/authorize → sign in → consent
 *                                     → /callback?code&state   (our origin)
 *   message event ◀── postMessage ─── relayPopupCallback(), then close()
 *   completeLogin(): check state, exchange code, verify ID token
 *
 * The popup only relays the callback URL. The PKCE verifier, state and nonce
 * never leave this page, which is also where the code is exchanged.
 */
export async function startPopupLogin(settings, { prompt, log }) {
  // Browsers only allow a popup opened directly by a click, not after an
  // `await`. So open an empty window first and point it at Sharpnr once
  // the URL is ready.
  const popup = window.open("", POPUP_NAME, popupFeatures(480, 680));
  if (!popup) {
    throw new Error("The popup was blocked. Allow popups for this site.");
  }

  let url;
  try {
    url = await authorizeUrl(settings, { prompt, log, popup: true });
  } catch (err) {
    popup.close();
    throw err;
  }
  log(`Opening ${url.origin}${url.pathname} in a popup`);
  popup.location.assign(url);

  const search = await waitForPopup(popup);
  log("Popup returned to /callback and closed");
  return completeLogin(search, { log });
}

/**
 * Runs first thing on page load. If this page is the popup landing on
 * /callback, hand the URL to the window that opened it and close. Returns
 * true in that case, so the app does not render.
 */
export function relayPopupCallback() {
  const state = new URLSearchParams(window.location.search).get("state");
  if (
    window.location.pathname !== "/callback" ||
    !state?.startsWith(POPUP_STATE_PREFIX)
  ) {
    return false;
  }
  let opener = null;
  try {
    // Reading `.origin` throws if the opener is another site; then we must
    // not hand it the code.
    if (window.opener?.location.origin === window.location.origin) {
      opener = window.opener;
    }
  } catch {
    // Cross-origin opener: fall through and finish in this window.
  }
  if (!opener) return false;

  // Target our own origin, so no other site can receive the message.
  opener.postMessage(
    { type: POPUP_MESSAGE, search: window.location.search },
    window.location.origin,
  );
  window.close();
  return true;
}

function waitForPopup(popup) {
  return new Promise((resolve, reject) => {
    const onMessage = (event) => {
      // Only accept the message from our own popup on our own origin.
      if (event.origin !== window.location.origin || event.source !== popup) {
        return;
      }
      if (event.data?.type !== POPUP_MESSAGE) return;
      cleanup();
      resolve(event.data.search);
    };
    // The user may close the window without finishing. Give a message that
    // was posted just before closing a moment to arrive.
    const timer = setInterval(() => {
      if (!popup.closed) return;
      clearInterval(timer);
      setTimeout(() => {
        cleanup();
        reject(new Error("The sign-in window was closed before finishing."));
      }, 500);
    }, 500);
    const cleanup = () => {
      clearInterval(timer);
      window.removeEventListener("message", onMessage);
    };
    window.addEventListener("message", onMessage);
  });
}

/** A window of the given size, centred over this one. */
function popupFeatures(width, height) {
  const left = Math.round(window.screenX + (window.outerWidth - width) / 2);
  const top = Math.round(window.screenY + (window.outerHeight - height) / 3);
  return `popup=yes,width=${width},height=${height},left=${left},top=${top}`;
}

/** Discovery, PKCE, state and nonce → the /oauth/authorize URL. */
async function authorizeUrl(settings, { prompt, log, popup = false }) {
  const config = await discover(settings.issuer, log);

  const verifier = randomString();
  const challenge = base64url(await sha256(verifier));
  const state = (popup ? POPUP_STATE_PREFIX : "") + randomString();
  const nonce = randomString();

  // Needed again on /callback. sessionStorage is per tab, so a login started
  // in another tab cannot be completed here. (In popup mode it is this tab,
  // the opener, that completes the login, so the popup never needs these.)
  sessionStorage.setItem(
    PENDING_KEY,
    JSON.stringify({
      state,
      nonce,
      verifier,
      issuer: settings.issuer,
      clientId: settings.clientId,
    }),
  );

  const url = new URL(config.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: settings.clientId,
    redirect_uri: redirectUri,
    scope: settings.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...(prompt ? { prompt } : {}),
  });
  return url;
}

// ---------------------------------------------------------------------------
// Step 2: back on /callback
// ---------------------------------------------------------------------------

export async function completeLogin(search, { log }) {
  const params = new URLSearchParams(search);
  const pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || "null");
  sessionStorage.removeItem(PENDING_KEY);

  if (!pending) {
    throw new Error(
      "No sign-in in progress in this tab. Was /callback reloaded or opened directly?",
    );
  }
  // `state` ties this response to the request *we* started. Without the
  // check, an attacker could feed us a code for their own account.
  if (params.get("state") !== pending.state) {
    throw new Error("State mismatch: this response is not for our request.");
  }
  log("state matches");

  if (params.get("error")) {
    const description = params.get("error_description");
    throw new Error(
      `${params.get("error")}${description ? `: ${description}` : ""}`,
    );
  }
  // RFC 9207: the server says who issued the response, which defeats
  // "mix-up" attacks when an app talks to several providers.
  if (params.get("iss") && params.get("iss") !== pending.issuer) {
    throw new Error(`iss mismatch: got ${params.get("iss")}`);
  }
  log("iss matches the issuer");

  const code = params.get("code");
  if (!code) throw new Error("No code in the callback URL.");

  const config = await discover(pending.issuer, log);
  const tokens = await tokenRequest(config, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: pending.clientId,
    code_verifier: pending.verifier,
  });
  log(`Code exchanged: got ${Object.keys(tokens).join(", ")}`);

  const idClaims = tokens.id_token
    ? await verifyIdToken(config, tokens.id_token, {
        clientId: pending.clientId,
        nonce: pending.nonce,
        log,
      })
    : null;

  return {
    issuer: pending.issuer,
    clientId: pending.clientId,
    tokens,
    idClaims,
    obtainedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Using the tokens
// ---------------------------------------------------------------------------

export async function fetchUserInfo(session, { log }) {
  const config = await discover(session.issuer, log);
  const response = await fetch(config.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${session.tokens.access_token}` },
  });
  if (!response.ok) {
    const challenge = response.headers.get("WWW-Authenticate");
    throw new Error(
      `UserInfo returned ${response.status}${challenge ? ` (${challenge})` : ""}`,
    );
  }
  log("UserInfo OK");
  return response.json();
}

/** Uses the refresh token. The server rotates it: the old one is now dead. */
export async function refresh(session, { log }) {
  const config = await discover(session.issuer, log);
  const tokens = await tokenRequest(config, {
    grant_type: "refresh_token",
    refresh_token: session.tokens.refresh_token,
    client_id: session.clientId,
  });
  log("Refreshed: new access token and a rotated refresh token");
  return {
    ...session,
    // A refresh response may omit the ID token; keep the one we verified.
    tokens: { ...session.tokens, ...tokens },
    obtainedAt: Date.now(),
  };
}

export async function revoke(session, { log }) {
  const config = await discover(session.issuer, log);
  const response = await fetch(config.revocation_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      token: session.tokens.refresh_token,
      token_type_hint: "refresh_token",
      client_id: session.clientId,
    }),
  });
  if (!response.ok) throw new Error(`Revocation returned ${response.status}`);
  log("Refresh token revoked (its whole rotation family is now dead)");
}

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

const discoveryCache = new Map();

async function discover(issuer, log) {
  if (!discoveryCache.has(issuer)) {
    const response = await fetch(`${issuer}/.well-known/openid-configuration`);
    if (!response.ok) {
      throw new Error(`Discovery failed: ${response.status} from ${issuer}`);
    }
    const config = await response.json();
    // The issuer in the document must be exactly the one we asked, or the
    // tokens' `iss` claim will not match either.
    if (config.issuer !== issuer) {
      throw new Error(
        `Issuer mismatch: settings say ${issuer}, server says ${config.issuer}`,
      );
    }
    log(`Discovery loaded from ${issuer}`);
    discoveryCache.set(issuer, config);
  }
  return discoveryCache.get(issuer);
}

async function tokenRequest(config, form) {
  const response = await fetch(config.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      `Token endpoint: ${body.error || response.status}${
        body.error_description ? ` (${body.error_description})` : ""
      }`,
    );
  }
  return body;
}

/**
 * Checks an ID token the way a real client must: signature against the
 * server's published key, then issuer, audience, expiry and nonce.
 */
async function verifyIdToken(config, idToken, { clientId, nonce, log }) {
  const [headerPart, payloadPart, signaturePart] = idToken.split(".");
  const header = decodeJwtPart(headerPart);
  const claims = decodeJwtPart(payloadPart);

  if (header.alg !== "RS256") throw new Error(`Unexpected alg ${header.alg}`);
  const jwks = await (await fetch(config.jwks_uri)).json();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error(`No key with kid ${header.kid} in the JWKS`);

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlDecode(signaturePart),
    new TextEncoder().encode(`${headerPart}.${payloadPart}`),
  );
  if (!valid) throw new Error("ID token signature is invalid");
  log(`ID token signature verified with key ${header.kid}`);

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== config.issuer) throw new Error("ID token: wrong iss");
  if (!audiences.includes(clientId)) throw new Error("ID token: wrong aud");
  if (claims.exp * 1000 < Date.now()) throw new Error("ID token: expired");
  if (claims.nonce !== nonce) throw new Error("ID token: nonce mismatch");
  log("ID token claims OK (iss, aud, exp, nonce)");

  return claims;
}

/** Reads a JWT's header or payload. Does NOT verify anything. */
export function decodeJwtPart(part) {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(part)));
}

/** The claims of a JWT, unverified; for display only. */
export function peekJwt(token) {
  try {
    return decodeJwtPart(token.split(".")[1]);
  } catch {
    return null;
  }
}

function randomString() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256(text) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
}

function base64url(bytes) {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
