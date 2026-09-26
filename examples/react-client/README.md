# React test client

A small React app for trying "Sign in with Sharpnr" against a local
sharp-oauth server. It is a **public client**: it has no client secret and
uses the Authorization Code flow with PKCE, like any browser app should.

It does every step by hand in [`src/oauth.js`](src/oauth.js) (no OAuth
library), so you can read exactly what a client sends and checks:

1. Loads the discovery document and checks its `issuer`.
2. Creates a PKCE verifier and S256 challenge, a `state` and a `nonce`, and
   redirects to `/oauth/authorize`.
3. On `/callback`, checks `state` and `iss`, then exchanges the code (with the
   verifier) at `/oauth/token`.
4. Verifies the ID token's RS256 signature against `/.well-known/jwks.json`,
   then its `iss`, `aud`, `exp` and `nonce`.
5. Buttons to call `/oauth/userinfo`, refresh (the refresh token rotates),
   and revoke.

A log at the bottom of the page shows each step as it happens.

## Run it

1. Start sharp-oauth (`cargo run` in the repository root). It listens on
   `http://localhost:3000`.
2. Open <http://localhost:3000/developer/apps/new>, sign in, and register an
   app:
   - Type: **Browser, mobile or desktop app**
   - Redirect URL: `http://localhost:5173/callback`
   - Scopes: `openid`, `profile`, `email`, `offline_access`
3. Start this app:

   ```bash
   cd examples/react-client
   npm install
   npm run dev
   ```

4. Open <http://localhost:5173>, paste the client ID, and click
   **Sign in with Sharpnr**.

To skip typing the client ID each time, `cp .env.example .env` and fill in
`VITE_SHARP_CLIENT_ID` (the page also remembers what you typed).

## Things to try

| Try                                | Expect                                                                          |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| Sign in a second time              | No consent screen: your approval was remembered                                 |
| **Sign in with popup**             | Sharpnr opens in a small window that closes itself when done                    |
| **Sign in (show consent again)**   | `prompt=consent` shows the consent screen anyway                                |
| **Sign in (force password)**       | `prompt=login` asks for your password again                                     |
| Deny on the consent screen         | Red banner: `access_denied`                                                     |
| Remove `offline_access` from Scope | No refresh token; the refresh button is disabled                                |
| **Revoke refresh token**           | The server kills that token and every token rotated from it                     |
| Delete the app in the portal       | Refresh fails at once; the access token (a JWT) works until it expires (15 min) |

## Popup sign-in

**Sign in with popup** does the same flow in a small window, like "Sign in
with Google". The popup lands on the same `/callback` URL (no extra redirect
URL to register), sends the URL to the main page with `postMessage`, and
closes. The main page then checks `state` and exchanges the code, so the PKCE
verifier never leaves it. See `startPopupLogin` and `relayPopupCallback` in
[`src/oauth.js`](src/oauth.js).

Tokens are kept in `sessionStorage` so a reload keeps you signed in while
testing. A production app should keep them in memory, or let its own backend
hold them.
