/**
 * IANA TLS Cipher Suite registry — canonical name → 2-byte wire code.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ DUPLICATED IN @browsercore/profiles/src/codes.ts                        │
 * │                                                                         │
 * │ The same IANA tables exist in @browsercore/profiles (codes.ts). This is │
 * │ intentional — no dependency between the two packages. When adding a     │
 * │ new cipher suite, update BOTH copies.                                   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * This is the single source of truth for cipher suite codes within
 * @browsercore/tls. The literal union `CipherSuite` in `types.ts` and the
 * wire-encoding logic in `client-hello.ts` both derive from this table.
 *
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */

/**
 * The name Chrome/Edge use in their cipher list to mark a GREASE slot (RFC 8701).
 * The real value is randomized per-connection (0x0a0a..0xfafa); validation accepts
 * any GREASE-pattern byte pair at a slot marked with this placeholder.
 */
export const CIPHER_GREASE_PLACEHOLDER = "TLS_GREASE_RESERVED_0";

/**
 * Selected IANA TLS Cipher Suite codes, keyed by the canonical suite name.
 *
 * Covers every suite the shipped browser profiles offer: TLS 1.3 AEAD suites,
 * TLS 1.2 ECDHE/RSA suites for middlebox compatibility, and legacy 3DES suites.
 * An unknown name surfaces as an error at validation time.
 */
export const CIPHER_SUITE_CODES: Readonly<Record<string, number>> = {
    [CIPHER_GREASE_PLACEHOLDER]: 0x0a0a,
    TLS_AES_128_GCM_SHA256: 0x1301,
    TLS_AES_256_GCM_SHA384: 0x1302,
    TLS_CHACHA20_POLY1305_SHA256: 0x1303,
    TLS_AES_128_CCM_SHA256: 0x1304,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca8,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xc013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: 0xc014,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: 0xc00a,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: 0xc023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: 0xc024,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: 0xc028,
    TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA: 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA256: 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256: 0x003d,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: 0xc008,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: 0xc012,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA: 0x000a,
};
