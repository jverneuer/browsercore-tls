/**
 * IANA TLS Signature Scheme registry — canonical name → 2-byte wire code.
 *
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
 */

export const SIGNATURE_SCHEME_CODES: Readonly<Record<string, number>> = {
    ecdsa_secp256r1_sha256: 0x0403,
    ecdsa_secp384r1_sha384: 0x0503,
    ecdsa_secp521r1_sha512: 0x0603,
    ecdsa_sha1: 0x0203,
    rsa_pss_rsae_sha256: 0x0804,
    rsa_pss_rsae_sha384: 0x0805,
    rsa_pss_rsae_sha512: 0x0806,
    rsa_pkcs1_sha256: 0x0401,
    rsa_pkcs1_sha384: 0x0501,
    rsa_pkcs1_sha512: 0x0601,
    rsa_pkcs1_sha1: 0x0201,
    ed25519: 0x0807,
};
