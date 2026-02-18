/**
 * Browser-side crypto for DataChannel hidden messages.
 * AES-GCM with 32-byte key (same key material as server BB84-derived key).
 * No base64 for transport of media; used only for small encrypted payloads.
 */
(function (global) {
  const IV_LEN = 12;
  const TAG_LEN = 16;

  async function importKey(keyB64) {
    const keyBytes = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function encrypt(plaintextBytes, key) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_LEN * 8 },
      key,
      plaintextBytes
    );
    const out = new Uint8Array(iv.length + cipher.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(cipher), iv.length);
    return out;
  }

  async function decrypt(ivCipherTag, key) {
    const iv = ivCipherTag.slice(0, IV_LEN);
    const cipher = ivCipherTag.slice(IV_LEN);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_LEN * 8 },
      key,
      cipher
    );
  }

  async function encryptHiddenMessage(keyB64, payload) {
    if (!keyB64) return null;
    const key = await importKey(keyB64);
    const json = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(json);
    const encrypted = await encrypt(bytes, key);
    return btoa(String.fromCharCode.apply(null, encrypted));
  }

  async function decryptHiddenMessage(keyB64, b64Cipher) {
    if (!keyB64 || !b64Cipher) return null;
    try {
      const key = await importKey(keyB64);
      const binary = atob(b64Cipher);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const dec = await decrypt(bytes, key);
      const json = new TextDecoder().decode(dec);
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  }

  global.WebRTCCrypto = {
    encryptHiddenMessage,
    decryptHiddenMessage,
    importKey
  };
})(typeof window !== 'undefined' ? window : self);
