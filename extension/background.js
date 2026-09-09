import init, { analyze_request } from './pkg/aurora.js';
import { sha256Hex, hmacSign } from './crypto.js';
import { getConfig, getPseudonym, getSigningKey, initialize, restoreState } from './state.js';

let wasmInitialized = false;
init().then(() => {
    wasmInitialized = true;
    console.log("🦀 Aurora WASM Engine Loaded");
});

const MAX_RETRIES = 3;
const INITIAL_DELAY = 1000; // 1 second
const MAX_SIZE = 5 * 1024 * 1024; // 5MB
// const SERVER = "https://app.auroraidentity.com/ingest";
const SERVER = "http://localhost:8080/ingest";

const delay = (ms) => new Promise(res => setTimeout(res, ms));

async function preparePayload(eventPayload) {
    const pseudonym  = getPseudonym();
    const signingKey = getSigningKey();
    const config     = getConfig();
    if (!pseudonym || !signingKey || !config) return;

    const requestId  = crypto.randomUUID();
    const timestamp  = Date.now();

    const eventJson = JSON.stringify(eventPayload);
    const eventHash = await sha256Hex(eventJson);

    const sigInput  = `${pseudonym}|${timestamp}|${requestId}|${eventHash}`;
    const signature = await hmacSign(signingKey, sigInput);

    return {
        tenant_id:      config.aurora_tenant_id,
        pseudonym:      pseudonym,
        signature:      signature,
        request_id:     requestId,
        timestamp:      timestamp,
        http_method:    eventPayload.method,
        domain:         eventPayload.url,
        metadata:       eventPayload.metadata
    };
}

async function sendTelemetry(eventPayload, attempt = 1) {
    try {
        const response = await fetch(SERVER, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json'},
            body: JSON.stringify(eventPayload),
            keepalive: true
        });

        if (!response.ok) {
            throw new Error(`Server responded with ${response.status} for request id: ${eventPayload.request_id}`);
        }

        console.log(`[telemetry] Successfully sent event.`);
    } catch (err) {
        if (attempt <= MAX_RETRIES) {
            const waitTime = attempt * INITIAL_DELAY; // Linear: 1s, 2s, 3s...
            await delay(waitTime);

            return sendTelemetry(eventPayload, attempt + 1);
        } else {
            console.error(`[telemetry] Max retries reached, request id: ${eventPayload.request_id}. Data lost.`, err);
        }
    }
}

function getRawBodyBytes(requestBody) {
    if (!requestBody) return new Uint8Array(0);

    // 1. Handle standard raw bytes (Multipart, JSON, Octet-streams)
    if (requestBody.raw && requestBody.raw.length > 0) {
        try {
            const totalLength = requestBody.raw.reduce((acc, part) => {
                return acc + (part.bytes ? part.bytes.byteLength : 0);
            }, 0);

            const combined = new Uint8Array(totalLength);
            let offset = 0;
            for (const part of requestBody.raw) {
                if (part.bytes) {
                    combined.set(new Uint8Array(part.bytes), offset);
                    offset += part.bytes.byteLength;
                }
            }
            return combined;
        } catch (e) {
            console.error("Error consolidating raw bytes:", e);
            return new Uint8Array(0);
        }
    }

    // 2. Handle parsed formData (application/x-www-form-urlencoded)
    if (requestBody.formData) {
        try {
            const params = new URLSearchParams();
            for (const [key, values] of Object.entries(requestBody.formData)) {
                values.forEach(value => params.append(key, value));
            }
            // Convert the string representation back to bytes for WASM
            return new TextEncoder().encode(params.toString());
        } catch (e) {
            console.error("Error encoding formData:", e);
            return new Uint8Array(0);
        }
    }

    return new Uint8Array(0);
}

function sanitizeDomain(domain) {
    if (!domain || domain === "null" || domain === "undefined") {
        return null;
    }
    try {
        const u = new URL(domain);
        if (!["http:", "https:"].includes(u.protocol)) return null;
        if (!u.host) return null;
        return u.protocol + "//" + u.host + u.pathname;
    } catch {
        return null;
    }
}

function collectDomain(details) {
    // 1. skip GETs, uninitialized wasm, or calls to our own server
    if (details.method === "GET"
        || !wasmInitialized
        || details.url === SERVER)
        return null;

    // 2. skip non-http protocols and local addresses
    let url;
    try {
        url = new URL(details.url);
    } catch {
        return null;
    }

    if (url.hostname === "localhost"
        || url.hostname.startsWith("127."))
        return null;

   // 3. sanitize domain — drop if invalid
    const domain = sanitizeDomain(details.url);
    if (!domain) return null;

    // 4. check MDM collection flag
    const config = getConfig();
    if (!config?.aurora_collection_enabled) return null;

    return domain;
}

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        const domain = collectDomain(details);
        if (!domain) return;

        const fullBody = getRawBodyBytes(details.requestBody);
        if (fullBody === new Uint8Array(0)) return;
        
        let bytesToAnalyze;
        if (fullBody.length > MAX_SIZE) {
            bytesToAnalyze = fullBody.slice(0, 8192);
        } else {
            bytesToAnalyze = fullBody;
        }

        // Run the bridge logic asynchronously so we don't block the browser thread
        (async () => {
            try {
                const metadataAnalysis = analyze_request(
                    domain,
                    details.method,
                    bytesToAnalyze, // the 8KB slice OR the full body
                    fullBody.length // actual size
                );

                const eventPayload = await preparePayload({
                    method: details.method,
                    url: domain,
                    metadata: metadataAnalysis
                });

                await sendTelemetry(eventPayload);
            } catch (e) {
                console.error("[telemetry] Sending browser telemetry failed:", e);
            }
        })();

        return {};
    },
    { 
        urls: [
            "http://*/*", 
            "https://*/*"
        ]
    },
    ["requestBody"]
);

chrome.runtime.onInstalled.addListener(() => initialize());

chrome.runtime.onStartup.addListener(() => restoreState());

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'managed') initialize();
});

restoreState();