/* Vendor public key for organisation licences (ECDSA P-256, JWK).
 * null = licensing not configured yet: every feature stays unlocked.
 * Create the key pair with tools/license-issuer.html, keep the PRIVATE key offline,
 * and paste ONLY the public key here, e.g.:
 * window.WASL_VENDOR_KEY = { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." };
 */
window.WASL_VENDOR_KEY = window.WASL_VENDOR_KEY || null;
