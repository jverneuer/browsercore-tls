/**
 * IANA TLS Supported Groups (named groups) registry — canonical name → 2-byte wire code.
 *
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */

export const NAMED_GROUP_CODES: Readonly<Record<string, number>> = {
    x25519: 0x001d,
    x448: 0x001e,
    secp256r1: 0x0017,
    secp384r1: 0x0018,
    secp521r1: 0x0019,
    ffdhe2048: 0x0100,
    ffdhe3072: 0x0101,
    // Chrome 124+ adds the hybrid post-quantum group. The draft Kyber768 code
    // (0x6399) shipped in Chrome 124–130; the final MLKEM768 code (0x11ec) has
    // been used since Chrome 131. Both appear at the front of the group list.
    X25519Kyber768: 0x6399,
    X25519MLKEM768: 0x11ec,
};
