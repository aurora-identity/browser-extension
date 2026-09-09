# What we tried that did not ship

This file records the designs that were built and then abandoned on the way to the code in
this repository. It is here so that a newcomer does not spend a week rediscovering a dead
end, and so that anyone who wants to pick one of these up again knows what state it was
left in.

The branches these came from live in the private repository, not in this one.

## A native binary reading the macOS Keychain

The first design for getting a secret onto the machine did not use browser policy at all.
A small Rust binary was installed at `/usr/local/bin`, registered as a Chrome native
messaging host through a manifest at
`/Library/Google/Chrome/NativeMessagingHosts/com.auroraidentity.aurora.json`, and the
extension talked to it with `chrome.runtime.sendNativeMessage`. The binary read an identity
ID and a customer ID out of the system Keychain and handed them back over stdout. There was
a `host_keys.js` in the extension that wrapped this, cached the answers in session storage,
and guarded against firing two concurrent requests for the same key.

Getting that binary onto a corporate Mac turned out to be a more serious problem than the
code itself. It needed a distribution archive signed with a Developer ID and notarised by
Apple, an installer that writes into system-level `/Library` and therefore needs root, a
`.entitlements` file, and Keychain access groups so that the binary could reach the item the
installer had written. Three branches went at the signing and access-group problem from
different angles and none of them came out clean.

What replaced it is much smaller. The tenant secret is pushed through MDM into Chrome managed
storage, which Chrome already delivers to the extension, so there is no second deployment
channel, no installer, no notarisation, and no native code on the machine at all. That is
the design in `state.js` today.

## An embedding model for classifying domains

There was an attempt to classify destinations with a real sentence embedding model running
on device, in a separate `domain-classifier` crate. Two models were tried in turn,
`all-MiniLM-L6-v2` first and then `BGE-Micro-v2`, with several rounds of refinement against
each.

The model was checked into the repository: a 34 MB `model.safetensors` and a tokenizer JSON
of about thirty thousand lines. That size is the plain reason it could not ship. A browser
extension carrying 34 MB of weights is not something you push to a fleet, and the
classification it produced did not earn that cost.

What survives instead is far cheaper and does a narrower job honestly: `signatures.rs`
identifies a file format from its first few bytes, and `pii_detector.rs` runs three
compiled regular expressions behind a fast byte-level pre-check. No model, no weights.

## A larger upload traffic analyser

Alongside the embedding work there was a much bigger traffic analysis module in Rust, about
five hundred and fifty lines added to the same `domain-classifier` crate, aimed at
characterising uploads in more depth.

It was not carried forward. The analysis that ships is the small pair of passes in
`crates/aurora`, which answer only two questions — what format is this, and does it look
like it contains personal data.

## Per-user Google Workspace sign-in

This one is worth reading before anyone proposes it again, because the idea is sound and it
solves a real problem the shipped design does not. It failed on a single practical detail.

The idea was that every user gets their own API key rather than sharing a tenant secret,
and that the whole thing keys off their work email. The extension would run a silent
`chrome.identity.launchWebAuthFlow` against Google with `interactive: false`, take the
access token out of the redirect fragment, post it to the backend at `/auth/exchange`, and
receive a per-user API key which it cached in local storage for an hour.

What killed it is that the silent flow was never silent. Setting `interactive: false` is
meant to make Chrome complete the flow without showing anything when it already can, and
fail quietly when it cannot. In practice it put a Google sign-in prompt in front of the
person every time. That defeated the entire point of the design. This extension is deployed
by an administrator across a fleet, and the person at the keyboard is not meant to be asked
to do anything, or even to notice. Interrupting every employee to have them authorise
telemetry about themselves is worse than not shipping the feature.

## Client-side batching with a flush alarm

An earlier design buffered events in `chrome.storage.local` rather than sending each one as
it happened. It flushed when the buffer reached fifty events or when a `chrome.alarms` timer
fired, whichever came first, sent up to a hundred events in a single signed batch, and put
the batch back at the front of the queue if the request failed.

It was not merged. What ships instead sends one event per request and retries three times
with a linear backoff before dropping it.

The idea itself is not wrong, and the durable local queue is a part worth having: today an
event is lost if all three retries fail.
