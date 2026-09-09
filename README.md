# Aurora Identity Browser Extension

A Chrome extension that watches outgoing requests from a managed browser, works out what
is being uploaded and whether it looks like personal data, and reports that to a server
your organisation runs. The analysis happens locally, in a small Rust module compiled to
WebAssembly. The request body itself never leaves the machine — only a short description
of it does.

It is built for a workplace deployment. An IT administrator pushes the configuration
through MDM policy, and the extension does nothing at all until that policy arrives.

## What it actually does

When Chrome is about to send a request, the extension gets a look at it before it goes
out. It ignores anything that is not interesting: GET requests, anything that is not HTTP
or HTTPS, anything aimed at `localhost` or a `127.x` address, and its own calls to the
reporting server. It also stops immediately unless the administrator has switched
collection on.

For everything that survives that filter, the extension pulls the raw bytes of the
request body together and hands them to the WebAssembly module. That module does two
things. It reads the first few bytes to identify the file format, so a PDF, a ZIP, a
Windows executable and a JPEG are told apart by their signature rather than by their
filename. Then it scans the bytes for three kinds of personal data: email addresses, US
social security numbers, and phone numbers. It reports only that it found one, never what
it found.

Bodies larger than 5 MB are not scanned in full. The extension takes the first 8 KB and
scans that, but still reports the true total size, so a large upload is visible as a large
upload even though only its opening is examined.

The result is then signed and posted to your server.

## What leaves the browser

One JSON object per request, and nothing else:

| Field | What it holds |
| --- | --- |
| `tenant_id` | Which customer the event belongs to |
| `pseudonym` | An opaque string standing in for the person, explained below |
| `signature` | Proof the payload came from a browser holding the tenant secret |
| `request_id` | A fresh UUID for this event |
| `timestamp` | Milliseconds since the epoch |
| `http_method` | `POST`, `PUT`, and so on |
| `domain` | The scheme, host and path of the request |
| `metadata` | `requestSize`, `fileTypeFromAnalysis`, and `piiDetected` |

`piiDetected` is a list of short strings such as `"email detected"`. The matched text is
never included.

## How the person is identified

The extension never sends the Google account or the email address. Instead it takes the
account identifier that Chrome exposes through `chrome.identity.getProfileUserInfo`,
which stays the same for the life of that account, and runs it through HMAC-SHA256 to
produce a pseudonym. Your server sees a stable opaque string and can tell one person’s
events apart from another’s, without ever holding the account itself.

The administrator deploys two values: a tenant identifier, which is sent with every event
so your server knows whose data it is, and a tenant secret, which never leaves the browser.
From the secret the extension derives two separate keys with HKDF-SHA256: one that turns
the account identifier into a pseudonym, and one that signs payloads. Keeping those two
jobs on different keys means neither operation can be used to produce a value that would
pass as the other. Both are created as non-extractable
`CryptoKey` objects, so nothing running in the extension can read their raw bytes back
out. The Google account identifier is never written to disk; only the finished pseudonym
is cached, in session storage, which Chrome clears when the browser closes.

The pseudonym hides the person from anyone who does not hold the tenant secret: the
network, another tenant, or anyone who ends up with a database of pseudonyms on its own.
The secret never leaves the browser, so it appears in no payload, no log and no proxy
trace. Your server does hold a copy, because it needs one to check signatures, so it can
compute the pseudonym for any account identifier it already has.

## Repository layout

```
extension/                  The extension source
  manifest.json             Manifest V3, permissions, managed storage schema
  background.js             Service worker: filters requests, builds and sends payloads
  state.js                  Reads MDM config, derives keys, computes the pseudonym
  crypto.js                 HKDF, HMAC and SHA-256 helpers over WebCrypto
  managed_schema.json       The policy keys an administrator can set

crates/aurora/              The Rust analysis module, compiled to WebAssembly
  src/lib.rs                The one function the extension calls
  src/signatures.rs         File format identification from magic bytes
  src/pii_detector.rs       Email, SSN and phone detection

deploy/                     A ready-to-edit macOS configuration profile
Makefile                    Builds the Rust module and minifies the extension
```

## Building it

You need a Rust toolchain, [`wasm-pack`](https://rustwasm.github.io/wasm-pack/), and
Node.js, which the build uses to run `terser` through `npx`.

```bash
make build
```

That compiles the Rust crate to WebAssembly, minifies the three JavaScript files, copies
the manifest and the policy schema, and leaves a loadable extension in `extension-dist/`.
It cleans up after itself, removing the generated `extension/pkg/` directory and running
`cargo clean`.

Load `extension-dist/` and not `extension/`. The source directory has no `pkg/` folder
until a build creates one, and `background.js` imports the WebAssembly module from there,
so loading the source directory directly will fail.

To load it: open `chrome://extensions`, switch on Developer mode, choose "Load unpacked",
and select `extension-dist/`.

The Rust tests run on their own:

```bash
cd crates/aurora && cargo test
```

## Configuring it

The extension reads its configuration from Chrome managed storage, which means it has to
be delivered by policy. Nothing is configurable from inside the browser, and there is no
options page, on purpose.

### The policy keys

These are the only values the extension reads. They are declared in
`extension/managed_schema.json`.

| Key | Type | What to put in it |
| --- | --- | --- |
| `aurora_tenant_id` | string | Your identifier for the customer. Sent with every event |
| `aurora_tenant_secret` | string | A 256-bit secret written as 64 hex characters. Never sent |
| `aurora_collection_enabled` | boolean | `true` to collect. Until it is true, nothing is inspected |

Generate the secret once per tenant, and handle it as a secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Your own extension key and ID

`extension/manifest.json` ships with a placeholder in its `key` field. You need to deal
with it before the extension will load:

- **Just trying it out?** Delete the `"key"` line. Chrome will assign an ID derived from
  the folder path, which is fine for local development.
- **Deploying to a fleet?** You need an ID that is the same on every machine, because your
  MDM policy has to name it. Either publish to the Chrome Web Store and use the ID it
  assigns you, or generate your own key pair and put the public half in `manifest.json`.

To generate your own pair:

```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out aurora-extension.pem
openssl rsa -in aurora-extension.pem -pubout -outform DER | base64 | tr -d "\n"
```

The second command prints the value for the `key` field. Keep the `.pem` file private and
out of version control. The extension ID that Chrome will derive from it is:

```bash
openssl rsa -in aurora-extension.pem -pubout -outform DER \
  | shasum -a 256 | head -c 32 | tr "0-9a-f" "a-p"
```

### Deploying the policy on macOS

`deploy/aurora_chrome_managed_policy.mobileconfig` is a configuration profile ready to
edit. Replace `YOUR_EXTENSION_ID`, which appears twice, `REPLACE_WITH_YOUR_TENANT_ID` and
`REPLACE_WITH_YOUR_64_CHARACTER_HEX_SECRET`. Then replace both `PayloadUUID` values with
fresh ones from `uuidgen`, because the two in the file are placeholders and every profile
is supposed to carry its own. Push it through your MDM as you would any other profile; for
a local test you can install it by hand from System Settings.

Once the profile lands, Chrome makes those values visible to the extension, and you can
confirm it worked at `chrome://policy` on the target machine.

On Windows the same two keys go under the registry path
`HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\YOUR_EXTENSION_ID\policy`, and on
Linux in a JSON file under `/etc/opt/chrome/policies/managed/`.

## Before you rely on this

A few things a newcomer should know:

`SERVER` in `background.js` points at `http://localhost:8080/ingest`, with the production
URL commented out on the line above. This repository is the client half only. The server
that receives these payloads lives at
[aurora-identity/server-public](https://github.com/aurora-identity/server-public). Point
that constant at whatever you are running before you expect anything to arrive.

`aurora_tenant_secret` is the secret everything else is built on. It signs payloads and it
derives pseudonyms, and it never leaves the browser. Anyone who obtains it can forge events
and can undo the pseudonym, so deploy it the way you would deploy any other secret.

The `domain` field keeps the full request path. If you want only hostnames, that is a
one-line change in `sanitizeDomain`.

Identity only works when the person is signed in to Chrome itself. Without that,
`chrome.identity.getProfileUserInfo` returns no identifier, and the extension logs a
warning and stops rather than sending anything unattributed.

Failed sends are retried three times with a linear backoff and then dropped. There is no
disk queue, so events are lost if the browser is offline for longer than that.

Several designs were built and dropped before this one.
[DESIGN-HISTORY.md](DESIGN-HISTORY.md) records what they were, how far each got, and why
it was abandoned.

## Extending the detectors

The detectors in `crates/aurora/src/pii_detector.rs` are a deliberately small set of
worked examples rather than an attempt at global coverage. The phone matcher recognises
German and Norwegian country codes, and the social security matcher implements the US
allocation rules. They are there to show the shape of the thing: a cheap byte-level
pre-check, then a compiled regular expression, then a validity check before anything is
reported.

Adding another is straightforward. Write the pattern, add it to the `detect_pii` function,
and extend the fast-path check so the scan still exits early on bodies that cannot match.
The same goes for `signatures.rs`, where a new file format is one more line of magic bytes.

If you need detectors for a particular country or data type and would rather not write
them yourself, get in touch.

## Getting in touch

Questions, bugs and patches are welcome as
[issues](https://github.com/aurora-identity/browser-extension-public/issues) on this
repository.

If you would like detectors built for your own data types, help deploying this across a
fleet, or consulting work around it, we are happy to help: https://github.com/georgismitev.

## Licence

The Aurora Identity Browser Extension uses the Business Source License 1.1 (BSL 1.1).

- It is free for individuals, hobbyists, researchers and open-source projects.
- It is free for organisations with fewer than 50 employees and under $1,000,000 in annual
  gross revenue.
- It is free for all internal use.
- Offering it to third parties as a hosted, SaaS or managed service requires a commercial
  licence from Aurora Identity.
- It becomes Apache 2.0 automatically on September 9, 2030.

Full terms are in [LICENSE](LICENSE).
