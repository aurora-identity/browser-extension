export function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

export function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function hkdfDeriveKey(masterKeyBytes, infoString) {
  const baseKey = await crypto.subtle.importKey(
    'raw', masterKeyBytes, { name: 'HKDF' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),       // zero salt — the master key is already high-entropy
      info: new TextEncoder().encode(infoString)
    },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,                             // non-extractable
    ['sign']
  );
}

export async function hmacSign(cryptoKey, message) {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return bytesToHex(sig);
}

export async function sha256Hex(message) {
  const data = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(hash);
}