import { hexToBytes, hkdfDeriveKey, hmacSign } from './crypto.js';

let _config = null;
let _pseudonymKey = null;
let _signingKey = null;
let _pseudonym = null;

export const getConfig     = () => _config;
export const getPseudonym  = () => _pseudonym;
export const getSigningKey = () => _signingKey;

async function deriveKeys(tenantSecret) {
  const masterBytes = hexToBytes(tenantSecret);
  _pseudonymKey = await hkdfDeriveKey(masterBytes, 'pseudonym-derivation');
  _signingKey   = await hkdfDeriveKey(masterBytes, 'payload-signing');
}

export async function initialize() {
  try {
    const managed = await chrome.storage.managed.get(null);
    if (managed?.aurora_tenant_id && managed?.aurora_tenant_secret) {
      _config = managed;
    }
  } catch (e) { /* managed storage not yet available */ }

  if (!_config) {
    console.log('[telemetry] Waiting for managed config...');
    return;
  }

  await deriveKeys(_config.aurora_tenant_secret);

  const userInfo = await chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' });
  if (!userInfo.id) {
    console.warn('[telemetry] No signed-in user');
    return;
  }

  _pseudonym = await hmacSign(_pseudonymKey, userInfo.id);
  console.log('[telemetry] Initialized, pseudonym and identity in place.');

  // Cache pseudonym for service worker restarts
  await chrome.storage.session.set({ pseudonym: _pseudonym, configLoaded: true });
}

export async function restoreState() {
  const session = await chrome.storage.session.get(['pseudonym', 'configLoaded']);
  if (session.configLoaded) {
    _pseudonym = session.pseudonym;
    // Re-derive keys (CryptoKey objects don't survive SW restarts)
    try {
      const managed = await chrome.storage.managed.get(null);
      _config = managed;
      await deriveKeys(_config.aurora_tenant_secret);
    } catch (e) { /* will retry on next event */ }
  } else {
    await initialize();
  }
}