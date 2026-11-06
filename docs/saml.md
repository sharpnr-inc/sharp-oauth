# SAML Explained: A Beginner's Guide with TypeScript

**SAML is not implemented in Sharp-OAuth yet.** This guide explains how the
protocol works. Its TypeScript code is a standalone learning demo, not part
of this server. For what the server does today, see
[oauth-flow.md](oauth-flow.md).

## What SAML is

SAML lets a person sign in once, at one trusted place, and then open many work
apps without a separate password for each. The name stands for Security
Assertion Markup Language. An *assertion* is a signed statement, such as "this
person is Sam, and they signed in a minute ago."

Imagine a company called Descovro that uses 30 apps. Without SAML, each
employee has 30 passwords, and when someone leaves, an admin must remove them
from 30 places. With SAML, one sign-in opens every app, and turning off one
account blocks them all.

**A passport is the easiest way to picture it.** Your government checks who
you are and gives you a passport. An airport in another country has never met
you, and it doesn't phone your government. It trusts the passport because it
can check that the passport is genuine.

SAML works the same way. One system checks who you are and gives you a signed
statement. You carry that statement to the app, and the app checks the
signature instead of asking for a password.

This guide follows one example from start to finish. Descovro and its employee
Sam are made up, Sharpnr is the sign-in system, and Jira is the app Sam wants
to open. The first half needs no coding knowledge, and the TypeScript comes
later.

## The three players

Every SAML sign-in involves exactly three players: a user, an identity
provider and a service provider.

| Player | What it does | In the passport story | In our example |
| --- | --- | --- | --- |
| User | The person signing in, using a web browser | The traveller | Sam |
| Identity provider (IdP) | Knows who people are and checks their password | The government | Sharpnr |
| Service provider (SP) | The app the person wants to use | The airport | Jira |

The important point is that **the app never sees the password**. Sam types it
only into Sharpnr. Jira receives a signed statement instead, so a break-in at
Jira exposes no Sharpnr passwords.

The browser also has a special job. It carries the messages between the IdP
and the SP, just as a traveller carries a passport. During a sign-in, Sharpnr
and Jira never need to talk to each other directly.

## The one-time setup

Before anyone can sign in, an admin connects the two systems once by copying a
few values between them. This step is called *federation*, and it's how Jira
learns to trust Sharpnr.

| Comes from | Value | What it is | Pasted into |
| --- | --- | --- | --- |
| Sharpnr (IdP) | Entity ID | Sharpnr's unique SAML name | Jira's admin settings |
| Sharpnr (IdP) | SSO URL | The address where users go to sign in | Jira's admin settings |
| Sharpnr (IdP) | Public certificate | The file used to check Sharpnr's signature | Jira's admin settings |
| Jira (SP) | Entity ID | Jira's unique SAML name | Sharpnr's app settings |
| Jira (SP) | ACS URL | The address where Sharpnr's answer is delivered | Sharpnr's app settings |

ACS stands for Assertion Consumer Service. It's a long name for "the page that
receives the signed statement." An entity ID often looks like a web address,
but it's only a name, so nothing needs to load at that address.

Many systems pack these values into one small XML file called *metadata*. The
admin can then upload a single file instead of copying each value by hand.

**The certificate is what makes the trust work.** Sharpnr creates a pair of
matching keys. The *private key* stays secret on Sharpnr's server and creates
signatures. The *public certificate* can be shared with anyone, and it can
only check signatures.

Think of a wax seal with a stamp only the king owns. Anyone can look at the
seal and recognize it, but nobody else can make it. If someone changes even
one letter of a signed message, the check fails.

**A real example:** for Jira Cloud, Descovro's site would be
`descovro.atlassian.net`. The admin makes these settings in Atlassian's admin
area, and Atlassian requires a [Guard Standard subscription and a verified
company
domain](https://support.atlassian.com/security-and-access-policies/docs/configure-saml-single-sign-on-with-an-identity-provider/).

## A sign-in, step by step

A SAML sign-in is a short round trip: the browser goes from the app to the IdP
and back, carrying one message each way. Here's what happens when Sam opens
Jira.

```text
    Jira (SP)                     Sam's browser                   Sharpnr (IdP)

        │   1. Sam opens the Jira site  │                               │
        │◀──────────────────────────────│                               │
        │  2. Redirect + login request  │                               │
        │──────────────────────────────▶│                               │
        │                               │ 3. Delivers the login request │
        │                               │──────────────────────────────▶│
        │                               │   4. Sharpnr's sign-in form   │
        │                               │◀──────────────────────────────│
        │                               │  5. Sam's email and password  │
        │                               │──────────────────────────────▶│
        │                               │  6. Signed response in a form │
        │                               │◀══════════════════════════════│
        │   7. Posts it to the ACS URL  │                               │
        │◀══════════════════════════════│                               │
        │  8. Signature OK, Jira opens  │                               │
        │──────────────────────────────▶│                               │
```

The browser carries every message, so Jira and Sharpnr never talk directly.
The double lines carry the signed response.

1. **Sam opens the Jira site.** Sam goes to `descovro.atlassian.net` and
   enters `sam@descovro.com`. Atlassian sees that this email domain is linked
   to Sharpnr.
2. **Jira creates a login request.** It redirects the browser to Sharpnr's SSO
   URL with the request attached.
3. **The browser delivers the request.** Sharpnr checks that it came from an
   app an admin registered.
4. **Sharpnr shows its sign-in form.** If Sam already signed in earlier,
   Sharpnr skips this step and the next. That's what makes it single sign-on.
5. **Sam enters a password.** It goes only to Sharpnr, so Jira never sees it.
6. **Sharpnr creates the signed response.** It says who Sam is and which app
   it's for. Unlike a passport, it expires in minutes.
7. **The browser delivers the response.** A hidden form posts it to Jira's ACS
   URL.
8. **Jira checks everything and opens.** It verifies the signature with the
   stored certificate and matches the email to Sam's account. After that, Jira
   uses its own normal session.

For Jira Cloud, [the email must match the Atlassian
account](https://support.atlassian.com/atlassian-cloud/kb/faq-implementing-saml-single-sign-on/).
If it doesn't, the sign-in can fail or create a new empty account.

**Why two different delivery methods?** A login request is small enough to fit
in a web address, and our demo's full address was 638 bytes. A response is too
large for that, at about 6,300 bytes of XML, so it travels in a form instead.
SAML calls these delivery methods *bindings*.

**Sign-ins can start in two places.** The flow above starts at the app, which
is called *SP-initiated* sign-in. If Sam clicks a Jira icon on a Sharpnr
dashboard instead, the flow is *IdP-initiated* and has no login request. That
makes it harder to protect, as the security section explains.

## What the messages look like

SAML messages are XML text, and a sign-in uses only two of them: the app's
**login request** and the IdP's **signed response**. Both samples below come
from a real run of this guide's code. Long values and some setup lines are
shortened so you can read them.

### The login request

The app's message is short. It says who is asking and where the answer should
go.

```xml
<samlp:AuthnRequest
    ID="_8397fba5..."
    IssueInstant="2026-11-06T07:19:46.684Z"
    Destination="http://localhost:3000/saml/sso"
    AssertionConsumerServiceURL="http://localhost:4000/saml/acs">
  <saml:Issuer>http://localhost:4000/saml/metadata</saml:Issuer>
</samlp:AuthnRequest>
```

The browser carries this message inside a web address. To fit, the XML is
compressed, then converted to plain characters with Base64:

```text
http://localhost:3000/saml/sso?SAMLRequest=nVNNb9pAEP0r1t7B...
```

That text looks scrambled, but it's only packed, not secret. Anyone who sees
it can unpack it and read the XML.

### The signed response

The IdP's answer is longer because it carries the signed statement about the
user.

```text
┌─ Response: the outer envelope ─────────────────────────────┐
│  Issuer      Who wrote this response                       │
│  Signature   Seals the whole response                      │
│  Status      Success or failure                            │
│                                                            │
│  ┌─ Assertion: the signed statement about Sam ──────────┐  │
│  │  Issuer              Who wrote this statement        │  │
│  │  Signature           Seals the assertion             │  │
│  │  Subject             NameID: sam@descovro.com        │  │
│  │  Conditions          Audience and expiry time        │  │
│  │  AuthnStatement      When Sam signed in              │  │
│  │  AttributeStatement  Extra facts about Sam           │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

The assertion sits inside the response, and each has its own signature.

Think of the response as an envelope and the assertion as the signed letter
inside it. Here is the same structure as real XML:

```xml
<samlp:Response
    ID="_b04d35df..."
    Destination="http://localhost:4000/saml/acs"
    InResponseTo="_8397fba5...">
  <saml:Issuer>http://localhost:3000/saml/metadata</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <saml:Assertion ID="_d0fb64f9...">
    <saml:Issuer>http://localhost:3000/saml/metadata</saml:Issuer>
    <ds:Signature>...</ds:Signature>

    <saml:Subject>
      <saml:NameID>sam@descovro.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            InResponseTo="_8397fba5..."
            NotOnOrAfter="2026-11-06T07:24:46.718Z"
            Recipient="http://localhost:4000/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions
        NotBefore="2026-11-06T07:19:46.718Z"
        NotOnOrAfter="2026-11-06T07:24:46.718Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://localhost:4000/saml/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement AuthnInstant="2026-11-06T07:19:46.718Z"/>

    <saml:AttributeStatement>
      <saml:Attribute Name="firstName">
        <saml:AttributeValue>Sam</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

The response looks large, but each part answers one simple question.

| Part | Question it answers | Why it matters |
| --- | --- | --- |
| `Issuer` | Who wrote this? | It must be an IdP the app trusts |
| `Signature` | Is it genuine and unchanged? | Changing one letter makes the check fail |
| `NameID` | Who is the user? | The app uses it to find the account |
| `Audience` | Which app is this for? | A statement made for another app is refused |
| `InResponseTo` | Which request does this answer? | It ties the answer to one real login attempt |
| `NotOnOrAfter` | When does this expire? | Here it's valid for 5 minutes |
| `Destination`, `Recipient` | Where should this be delivered? | Stops it being used at a different address |
| `AttributeValue` | What else should the app know? | Extra details, such as a first name |

This example has two signatures, one on the assertion and one on the whole
response. Some apps require one or the other, so signing both works with more
apps.

A signed response is sealed, not hidden. Anyone who can see it can read Sam's
email, so the connection must always use HTTPS. SAML also has optional
encryption, but not every app accepts it. Jira Cloud, for example, [requires
responses that are signed and not
encrypted](https://support.atlassian.com/security-and-access-policies/docs/configure-saml-single-sign-on-with-an-identity-provider/).

## Build the app in TypeScript

The app side takes about 60 lines, because a tested library does the dangerous
work. We'll build a tiny app that plays Jira's role, on `localhost:4000`. In
the next section, a tiny IdP on `localhost:3000` will play Sharpnr's role.

The code in this guide was run from a clean folder on Node 22 with
`@node-saml/node-saml` 5.2.0 and `xml-crypto` 6.4.0.

### Set up the project

These commands install the libraries and create the IdP's key pair. The
`openssl` command makes a private key and a public certificate, as described
in the setup section.

```bash
mkdir saml-demo && cd saml-demo
npm init -y
npm pkg set type=module
npm install express@4 @node-saml/node-saml@5 xml-crypto@6 @xmldom/xmldom@0.9
npm install -D tsx typescript @types/express@4 @types/node

openssl req -x509 -newkey rsa:2048 -nodes -keyout idp-key.pem \
  -out idp-cert.pem -days 365 -subj "/CN=Demo IdP"
```

### The app: `sp.ts`

```ts
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import express from "express";
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";

const saml = new SAML({
  // Who we are: the two values we give to the IdP.
  issuer: "http://localhost:4000/saml/metadata",
  callbackUrl: "http://localhost:4000/saml/acs",

  // Who we trust: the three values the IdP gave us.
  idpIssuer: "http://localhost:3000/saml/metadata",
  entryPoint: "http://localhost:3000/saml/sso",
  idpCert: readFileSync("idp-cert.pem", "utf8"),

  // Safety settings. Accept only signed answers to requests we really sent,
  // and accept each answer only once.
  wantAuthnResponseSigned: true,
  wantAssertionsSigned: true,
  validateInResponseTo: ValidateInResponseTo.always,
  rejectReplayedAssertions: true,
});

// A real app would keep sessions in a database or Redis.
const sessions = new Map<string, string>();

const app = express();

app.get("/", (req, res) => {
  const sessionId = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
  const email = sessionId ? sessions.get(sessionId) : undefined;
  if (!email) return res.redirect("/login");
  res.type("text").send(`Hello, ${email}! You are signed in.`);
});

// Step 1: send the browser to the IdP with a login request.
app.get("/login", async (_req, res) => {
  const url = await saml.getAuthorizeUrlAsync("/", {});
  res.redirect(url);
});

// Step 2: the browser comes back here with the signed response.
app.post("/saml/acs", express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const { profile } = await saml.validatePostResponseAsync(req.body);
    if (!profile) return res.status(401).send("Sign-in failed");

    // Everything was verified, so now we can trust the email.
    const sessionId = randomUUID();
    sessions.set(sessionId, profile.nameID);
    res.cookie("sid", sessionId, { httpOnly: true, sameSite: "lax" });

    // RelayState comes through the browser, so never trust it blindly.
    const next = String(req.body.RelayState ?? "/");
    res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
  } catch (error) {
    console.error("Rejected SAML response:", (error as Error).message);
    res.status(401).send("Sign-in failed");
  }
});

app.listen(4000, () => console.log("App running at http://localhost:4000"));
```

### What the code does

1. `new SAML(...)` holds the values from the one-time setup. Compare it with
   the setup table and you'll see the same five items.
2. `/login` builds the login request and redirects the browser to the IdP.
3. `/saml/acs` is the ACS URL. The line that calls `validatePostResponseAsync`
   checks the signature, expiry, audience and matching request, and throws an
   error if anything fails.
4. After that check, SAML's job is finished. The app creates its own normal
   session and cookie, so the next page doesn't involve the IdP at all.

`RelayState` is a bookmark. It holds the page the user wanted, travels with
the messages and comes back unchanged. Our app checks that it's a local path,
so an attacker can't use it to redirect someone to another site.

## Build the identity provider in TypeScript

The IdP has four jobs: read the login request, check the user, build the
signed statement and send it back. This code is for learning only. Most
companies should use an established IdP product, because real ones add many
protections this demo skips.

### Build and sign the statement: `saml-response.ts`

This file creates the XML you saw earlier and adds the two signatures.

```ts
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { SignedXml } from "xml-crypto";

const IDP_ENTITY_ID = "http://localhost:3000/saml/metadata";
const privateKey = readFileSync("idp-key.pem", "utf8");
const publicCert = readFileSync("idp-cert.pem", "utf8");

export interface ResponseInput {
  requestId: string; // the ID of the login request we are answering
  spEntityId: string; // who this statement is for
  acsUrl: string; // where it will be delivered
  email: string;
  firstName: string;
}

// Stops a value such as "<admin>" from changing the XML's structure.
export function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildResponseXml(input: ResponseInput, now: Date): string {
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  const requestId = escapeXml(input.requestId);
  const acsUrl = escapeXml(input.acsUrl);

  return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" Version="2.0" IssueInstant="${issuedAt}" Destination="${acsUrl}" InResponseTo="${requestId}">
  <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_${randomUUID()}" Version="2.0" IssueInstant="${issuedAt}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(input.email)}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="${requestId}" NotOnOrAfter="${expiresAt}" Recipient="${acsUrl}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${issuedAt}" NotOnOrAfter="${expiresAt}">
      <saml:AudienceRestriction>
        <saml:Audience>${escapeXml(input.spEntityId)}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issuedAt}" SessionIndex="_${randomUUID()}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="firstName">
        <saml:AttributeValue>${escapeXml(input.firstName)}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
}

// Adds a digital signature to the Assertion or the Response element.
function sign(xml: string, element: "Assertion" | "Response"): string {
  const signer = new SignedXml({
    privateKey,
    publicCert,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });

  const path = `//*[local-name(.)='${element}']`;
  signer.addReference({
    xpath: path,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
  });

  // SAML requires the signature to come straight after <Issuer>.
  signer.computeSignature(xml, {
    prefix: "ds",
    location: { reference: `${path}/*[local-name(.)='Issuer']`, action: "after" },
  });
  return signer.getSignedXml();
}

export function buildSignedResponse(input: ResponseInput, now = new Date()): string {
  const xml = buildResponseXml(input, now);
  // Sign the inner statement first, then the outer envelope around it.
  return sign(sign(xml, "Assertion"), "Response");
}
```

### Handle the browser: `idp.ts`

This file is the IdP's web server. It reads the login request, shows the
sign-in form and returns the signed response.

```ts
import { randomUUID } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { DOMParser } from "@xmldom/xmldom";
import express from "express";
import { buildSignedResponse, escapeXml } from "./saml-response.ts";

const ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

// The apps an admin has registered: entity ID -> ACS URL.
const serviceProviders = new Map([
  ["http://localhost:4000/saml/metadata", "http://localhost:4000/saml/acs"],
]);

// Demo only. A real IdP stores slow, salted password hashes in a database.
const users = new Map([
  ["sam@descovro.com", { password: "demo-password", firstName: "Sam" }],
]);
const sessions = new Map<string, string>();

// Unpacks and reads a login request. Treat it as untrusted input.
function readLoginRequest(samlRequest: string) {
  const compressed = Buffer.from(samlRequest, "base64");
  const xml = inflateRawSync(compressed, { maxOutputLength: 64 * 1024 }).toString("utf8");
  if (xml.includes("<!DOCTYPE")) throw new Error("DOCTYPE is not allowed");

  const root = new DOMParser().parseFromString(xml, "text/xml").documentElement;
  const issuer = root?.getElementsByTagNameNS(ASSERTION_NS, "Issuer")[0]?.textContent?.trim();
  const requestId = root?.getAttribute("ID");
  const askedAcsUrl = root?.getAttribute("AssertionConsumerServiceURL");
  if (!issuer || !requestId) throw new Error("Login request is incomplete");

  // The most important check: only reply to an address an admin registered.
  const acsUrl = serviceProviders.get(issuer);
  if (!acsUrl) throw new Error("Unknown service provider");
  if (askedAcsUrl && askedAcsUrl !== acsUrl) throw new Error("ACS URL is not registered");

  return { requestId, spEntityId: issuer, acsUrl };
}

// The browser delivers the signed response by submitting this form.
function continuePage(samlRequest: string, relayState: string, email: string): string {
  const request = readLoginRequest(samlRequest);
  const firstName = users.get(email)!.firstName;
  const xml = buildSignedResponse({ ...request, email, firstName });
  const samlResponse = Buffer.from(xml).toString("base64");

  return `<!doctype html>
<form method="post" action="${escapeXml(request.acsUrl)}">
  <input type="hidden" name="SAMLResponse" value="${samlResponse}">
  <input type="hidden" name="RelayState" value="${escapeXml(relayState)}">
  <button>Continue</button>
</form>`;
}

function signInPage(samlRequest: string, relayState: string): string {
  return `<!doctype html>
<form method="post" action="/saml/signin">
  <input type="hidden" name="SAMLRequest" value="${escapeXml(samlRequest)}">
  <input type="hidden" name="RelayState" value="${escapeXml(relayState)}">
  <input name="email" type="email" placeholder="Email">
  <input name="password" type="password" placeholder="Password">
  <button>Sign in</button>
</form>`;
}

const app = express();
app.use(express.urlencoded({ extended: false }));

// The SSO URL: the app sends the browser here with a login request.
app.get("/saml/sso", (req, res) => {
  const samlRequest = String(req.query.SAMLRequest ?? "");
  const relayState = String(req.query.RelayState ?? "");
  try {
    readLoginRequest(samlRequest);

    // Already signed in? Then no password is needed. That's "single sign-on".
    const sessionId = /(?:^|;\s*)idp_sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    const email = sessionId ? sessions.get(sessionId) : undefined;
    res.send(
      email
        ? continuePage(samlRequest, relayState, email)
        : signInPage(samlRequest, relayState),
    );
  } catch (error) {
    console.error("Rejected login request:", (error as Error).message);
    res.status(400).send("This sign-in request is not valid");
  }
});

// The sign-in form posts here.
app.post("/saml/signin", (req, res) => {
  const { email, password, SAMLRequest, RelayState } = req.body;
  const user = users.get(email);
  if (!user || user.password !== password) {
    return res.status(401).send(signInPage(SAMLRequest, RelayState));
  }
  try {
    const sessionId = randomUUID();
    sessions.set(sessionId, email);
    res.cookie("idp_sid", sessionId, { httpOnly: true, sameSite: "lax" });
    res.send(continuePage(SAMLRequest, RelayState, email));
  } catch (error) {
    console.error("Rejected login request:", (error as Error).message);
    res.status(400).send("This sign-in request is not valid");
  }
});

app.listen(3000, () => console.log("IdP running at http://localhost:3000"));
```

### What the code does

1. `readLoginRequest` unpacks the request and checks it against the list of
   registered apps. The ACS URL must match exactly, or a fake request could
   trick the IdP into sending Sam's signed statement to an attacker.
2. `/saml/sso` looks for an existing IdP session. If Sam is already signed in,
   there's no password step, and that's the "single" in single sign-on.
3. `buildSignedResponse` creates the statement, with a 5-minute expiry, and
   signs it.
4. `continuePage` puts the response in a hidden form field, and the browser
   delivers it when the user clicks Continue. Many IdPs submit this form
   automatically with a small script.

### Run it

Start each server in its own terminal:

```bash
npx tsx idp.ts
npx tsx sp.ts
```

Open `http://localhost:4000` and sign in with `sam@descovro.com` and
`demo-password`. Click **Continue**, and you should see:

```text
Hello, sam@descovro.com! You are signed in.
```

To see single sign-on work, delete the app's `sid` cookie in your browser's
developer tools and reload. The IdP remembers you, so it skips the password
and shows only **Continue**.

## How SAML breaks, and what keeps it safe

SAML is safe only when every check runs, because one missing check can let an
attacker sign in as someone else. We ran the 12 attacks below against this
guide's code, and all 12 were rejected.

| Attack | What the attacker tries | What stopped it |
| --- | --- | --- |
| Changed email | Edits `sam@` to `ceo@` in a real response | The signature no longer matched |
| Removed signature | Deletes the signatures and sends the edited response | The app requires a valid signature |
| Forged signature | Signs a fake response with their own key | Only the stored IdP certificate is trusted |
| Signature wrapping | Adds a fake assertion beside the signed one (tried before and after it) | The signature check failed |
| Replay | Sends a used response again | Each request ID works only once |
| Unrequested response | Sends a real signed response for a request the app never made | No matching request exists |
| Wrong app | Reuses a statement made for a different app | The `Audience` didn't match |
| Old statement | Sends a statement issued 10 minutes earlier | It had passed its 5-minute expiry |
| Fake app | Asks the IdP for a statement from an unregistered app | The app isn't on the registered list |
| Stolen delivery | Uses a real app's name with the attacker's ACS URL | The ACS URL didn't match the registered one |
| XML bomb | Hides a `DOCTYPE` entity trick in the login request | `DOCTYPE` is refused |
| Compression bomb | Packs 10 MB of data into a small request | Unpacking stops at 64 KB |

**Signature wrapping is the most famous SAML attack.** Picture a signed
contract with a fake page stapled to it. One person checks the signed page,
while another person acts on the fake one.

This happened in a real library in 2025. In
[ruby-saml](https://thehackernews.com/2025/03/github-uncovers-new-ruby-saml.html),
two XML parsers read the same document differently. An attacker holding one
valid signature could forge assertions and sign in as any user.

### Rules for real systems

These rules follow the [OWASP SAML Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html).

- **Never write signature checks yourself.** Use a maintained library and keep
  it updated.
- **Trust only the certificate you stored.** Never trust a key that arrives
  inside the message.
- **Use strong algorithms.** Use RSA keys of at least 2048 bits and SHA-256 or
  better, and reject SHA-1.
- **Prefer logins that start at the app.** When a login starts at the IdP,
  there's no request to match the response against.
- **Keep statements short-lived and single-use.** Check expiry times, and
  remember which responses you've already accepted.

### What this demo doesn't cover

The demo proves that these two small programs work together. It hasn't been
tested with real Jira, and it isn't ready for production.

- **Delivery address checks:** the [node-saml
  docs](https://github.com/node-saml/node-saml) say version 5.2.0 doesn't yet
  enforce `Recipient` or `Destination`. The next major version will, so a
  production app should add these checks.
- **More than one server:** request IDs live in one server's memory. Several
  servers need a shared cache.
- **Clock differences:** a small time difference between servers can cause
  rejections. Keep clocks synced with NTP, and set `acceptedClockSkewMs` if
  needed.
- **The IdP's sign-in:** a real IdP needs hashed passwords, CSRF protection,
  rate limits, two-step login, session expiry and HTTPS.
- **Certificate renewal:** apps store the IdP's certificate, so changing it
  needs a planned handover with every app.

## SAML compared with OAuth 2.0 and OpenID Connect

Use SAML when a business app requires it, OpenID Connect for sign-in in new
apps, and OAuth 2.0 when an app needs API access. SAML and OpenID Connect both
answer "who is this person?" OAuth 2.0 answers a different question: "what may
this app do?"

|  | SAML 2.0 | OAuth 2.0 | OpenID Connect |
| --- | --- | --- | --- |
| Main question | Who is this person? | What may this app do? | Who is this person? |
| Format | XML | HTTP and JSON | Built on OAuth 2.0, with JSON tokens |
| What the app receives | Signed assertion | Access token | ID token, usually with an access token |
| Common use | Employee sign-in to business apps | Letting an app call an API | "Sign in with..." on web and mobile |
| Does the app call the provider during sign-in? | No, the browser carries the messages | Yes, to get a token | Yes, to get tokens |
| Fit for mobile apps | Awkward | Good | Good |

Think of OAuth 2.0 as a hotel key card that opens only your room, and SAML as
the passport you show at the front desk. OpenID Connect adds that passport
check to the key card system.

One product can offer all three. An identity provider like Sharpnr can use
OpenID Connect for new apps, and add SAML for business apps such as Jira
Cloud.

## Glossary

| Term | Plain meaning |
| --- | --- |
| ACS URL | The app's page that receives the signed response |
| Assertion | The signed statement about the user |
| Attribute | An extra fact about the user, such as a first name |
| AuthnRequest | SAML's name for the login request |
| Base64 | A way to write data as plain characters. It packs data but doesn't hide it |
| Binding | How a message travels, such as in a web address or a hidden form |
| Certificate | The public file used to check the IdP's signature |
| Entity ID | A unique name for an IdP or an app |
| Federation | The trust set up between an IdP and an app |
| Identity provider (IdP) | The system that checks who a person is |
| Metadata | An XML file holding a system's SAML settings |
| NameID | The value that identifies the user, often an email |
| Private key | The secret that creates signatures |
| RelayState | A bookmark for the page the user wanted |
| Service provider (SP) | The app the user wants to open |
| Signature | Proof that a message is genuine and unchanged |
| SSO URL | The IdP address where users are sent to sign in |

## Next steps

1. Run the demo with your browser's Network tab open, and find the
   `SAMLRequest` and `SAMLResponse` values.
2. Paste a `SAMLResponse` into a Base64 decoder and match its parts to the
   table in this guide.
3. Read Atlassian's [SAML setup
   guide](https://support.atlassian.com/security-and-access-policies/docs/configure-saml-single-sign-on-with-an-identity-provider/)
   to see a real app's settings.

## Sources

- [Configure SAML single sign-on with an identity
  provider](https://support.atlassian.com/security-and-access-policies/docs/configure-saml-single-sign-on-with-an-identity-provider/),
  Atlassian
- [FAQ: Implement SAML single sign-on in Atlassian Cloud
  apps](https://support.atlassian.com/atlassian-cloud/kb/faq-implementing-saml-single-sign-on/),
  Atlassian
- [SAML Security Cheat
  Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html),
  OWASP
- [ruby-saml
  vulnerabilities](https://thehackernews.com/2025/03/github-uncovers-new-ruby-saml.html),
  The Hacker News
- [node-saml](https://github.com/node-saml/node-saml) and
  [xml-crypto](https://github.com/node-saml/xml-crypto) documentation
