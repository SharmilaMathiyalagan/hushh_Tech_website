/**
 * AES-256-GCM encryption utility
 * Replaces insecure btoa() encoding in onboarding step 13
 */

const getEncryptionKey = async (): Promise<CryptoKey> => {
  const rawKey = import.meta.env.VITE_ENCRYPTION_KEY;

  if (!rawKey) {
    throw new Error(
      '[cryptoUtils] VITE_ENCRYPTION_KEY is not set. ' +
      'Refusing to encrypt sensitive data with a fallback key.'
    );
  }

  const keyBytes = new TextEncoder().encode(rawKey.padEnd(32, '0').slice(0, 32));
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
};

export const encryptSensitiveData = async (plaintext: string): Promise<string> => {
  const key = await getEncryptionKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return btoa(String.fromCharCode(...combined));
};

