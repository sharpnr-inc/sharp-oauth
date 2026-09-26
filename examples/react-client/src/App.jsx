import { useEffect, useState } from "react";
import {
  completeLogin,
  fetchUserInfo,
  loadSession,
  loadSettings,
  peekJwt,
  redirectUri,
  refresh,
  revoke,
  saveSession,
  saveSettings,
  startLogin,
  startPopupLogin,
} from "./oauth.js";

// React's StrictMode runs effects twice in development. The callback must be
// handled exactly once (the code is one-time), so remember the promise.
let callbackOnce = null;

export default function App() {
  const [settings, setSettings] = useState(loadSettings);
  const [session, setSession] = useState(loadSession);
  const [userInfo, setUserInfo] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(window.location.pathname === "/callback");
  const [logs, setLogs] = useState([]);

  const log = (message) =>
    setLogs((lines) => [...lines, { at: new Date(), message }]);

  useEffect(() => {
    if (window.location.pathname !== "/callback") return;
    callbackOnce ??= completeLogin(window.location.search, { log });
    callbackOnce
      .then((result) => {
        saveSession(result);
        setSession(result);
      })
      .catch((err) => setError(err.message))
      .finally(() => {
        // Drop ?code=… from the address bar and history.
        window.history.replaceState(null, "", "/");
        setBusy(false);
      });
  }, []);

  async function run(action) {
    setError(null);
    setBusy(true);
    try {
      await action();
    } catch (err) {
      setError(err.message);
      log(`Error: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }

  const signIn = (prompt) =>
    run(() => startLogin(saveSettings(settings), { prompt, log }));

  const signInWithPopup = () =>
    run(async () => {
      const result = await startPopupLogin(saveSettings(settings), { log });
      saveSession(result);
      setSession(result);
    });

  const signOut = () => {
    saveSession(null);
    setSession(null);
    setUserInfo(null);
    log("Signed out locally (tokens forgotten)");
  };

  return (
    <div className="page">
      <header className="top">
        <span className="logo" aria-hidden="true">
          <svg viewBox="0 0 64 64">
            <polygon points="8,56 18,8 32,8" fill="currentColor" />
            <polygon points="8,56 38,10 50,20" fill="currentColor" />
            <polygon points="8,56 56,28 56,46" fill="#ec3013" />
          </svg>
        </span>
        <div>
          <h1>Sharpnr test client</h1>
          <p className="muted">
            A React app that signs in with Sharpnr (Authorization Code + PKCE).
          </p>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      {busy && !session && (
        <div className="card">
          Working… (finish signing in if a window opened)
        </div>
      )}

      {!busy && !session && (
        <SignedOut
          settings={settings}
          setSettings={setSettings}
          onSignIn={signIn}
          onSignInWithPopup={signInWithPopup}
        />
      )}

      {session && (
        <SignedIn
          session={session}
          userInfo={userInfo}
          busy={busy}
          onUserInfo={() =>
            run(async () => setUserInfo(await fetchUserInfo(session, { log })))
          }
          onRefresh={() =>
            run(async () => {
              const next = await refresh(session, { log });
              saveSession(next);
              setSession(next);
            })
          }
          onRevoke={() =>
            run(async () => {
              await revoke(session, { log });
              const next = {
                ...session,
                tokens: { ...session.tokens, refresh_token: undefined },
              };
              saveSession(next);
              setSession(next);
            })
          }
          onSignOut={signOut}
        />
      )}

      <section className="card">
        <h2>Log</h2>
        {logs.length === 0 ? (
          <p className="muted">
            Nothing yet. Each protocol step shows up here.
          </p>
        ) : (
          <ol className="log">
            {logs.map((line, index) => (
              <li key={index}>
                <time>{line.at.toLocaleTimeString()}</time> {line.message}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

function SignedOut({ settings, setSettings, onSignIn, onSignInWithPopup }) {
  const update = (field) => (event) =>
    setSettings({ ...settings, [field]: event.target.value });
  const issuer = settings.issuer.replace(/\/+$/, "");

  return (
    <section className="card">
      <h2>1. Register this app</h2>
      <p>
        In the{" "}
        <a
          href={`${issuer}/developer/apps/new`}
          target="_blank"
          rel="noreferrer"
        >
          Sharpnr developer portal
        </a>
        , create a <strong>Browser, mobile or desktop app</strong> (public, no
        secret) with this redirect URL:
      </p>
      <pre className="value">{redirectUri}</pre>

      <h2>2. Settings</h2>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onSignIn();
        }}
      >
        <label>
          Issuer
          <input value={settings.issuer} onChange={update("issuer")} required />
        </label>
        <label>
          Client ID
          <input
            value={settings.clientId}
            onChange={update("clientId")}
            placeholder="sharp_client_…"
            required
          />
        </label>
        <label>
          Scope
          <input value={settings.scope} onChange={update("scope")} required />
        </label>

        <div className="actions">
          <button type="submit" className="primary">
            Sign in with Sharpnr
          </button>
          <button type="button" onClick={onSignInWithPopup}>
            Sign in with popup
          </button>
          <button type="button" onClick={() => onSignIn("login")}>
            Sign in (force password)
          </button>
          <button type="button" onClick={() => onSignIn("consent")}>
            Sign in (show consent again)
          </button>
        </div>
      </form>
    </section>
  );
}

function SignedIn({
  session,
  userInfo,
  busy,
  onUserInfo,
  onRefresh,
  onRevoke,
  onSignOut,
}) {
  const claims = session.idClaims || {};
  const accessClaims = peekJwt(session.tokens.access_token);
  const expiresAt = accessClaims?.exp
    ? new Date(accessClaims.exp * 1000)
    : null;
  const display =
    userInfo?.name || claims.name || userInfo?.email || claims.sub;

  return (
    <>
      <section className="card profile">
        <span className="avatar" aria-hidden="true">
          {(display || "?").charAt(0).toUpperCase()}
        </span>
        <div>
          <h2>Signed in{display ? ` as ${display}` : ""}</h2>
          <p className="muted">
            sub <code>{claims.sub}</code>
            {expiresAt && (
              <> · access token expires {expiresAt.toLocaleTimeString()}</>
            )}
          </p>
        </div>
      </section>

      <div className="actions">
        <button className="primary" onClick={onUserInfo} disabled={busy}>
          Call /oauth/userinfo
        </button>
        <button
          onClick={onRefresh}
          disabled={busy || !session.tokens.refresh_token}
          title={
            session.tokens.refresh_token ? "" : "Needs the offline_access scope"
          }
        >
          Refresh tokens
        </button>
        <button
          onClick={onRevoke}
          disabled={busy || !session.tokens.refresh_token}
        >
          Revoke refresh token
        </button>
        <button onClick={onSignOut}>Sign out</button>
      </div>

      {userInfo && <Json title="UserInfo response" value={userInfo} />}
      <Json
        title="ID token claims (signature verified)"
        value={session.idClaims}
      />
      <Json
        title="Access token claims (decoded, not verified)"
        value={accessClaims}
      />
      <Json
        title="Token response"
        value={{
          ...session.tokens,
          obtained_at: new Date(session.obtainedAt).toISOString(),
        }}
        collapsed
      />
    </>
  );
}

function Json({ title, value, collapsed = false }) {
  return (
    <section className="card">
      <details open={!collapsed}>
        <summary>
          <h2>{title}</h2>
        </summary>
        <pre className="json">{JSON.stringify(value, null, 2)}</pre>
      </details>
    </section>
  );
}
