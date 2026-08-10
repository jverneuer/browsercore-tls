/**
 * HelloRetryRequest handling (RFC 8446 §4.1.3, §4.2.2, §4.4.1).
 *
 * A HelloRetryRequest (HRR) is a special ServerHello: it has the same wire
 * format but carries the sentinel value `CF21AD74…` in its `random` field. The
 * server sends it when the client's initial ClientHello is unacceptable (e.g.
 * the key-share group was not in the server's preference list). On receiving an
 * HRR the client must:
 *
 *   1. Replace the transcript prefix with a synthetic `message_hash` message
 *      (§4.4.1): `Hash(ClientHello_1)` wrapped in a handshake header.
 *   2. Parse the HRR extensions — `key_share` carries only `selected_group`
 *      (2 bytes, no key-exchange data), and `cookie` is an opaque anti-DoS blob.
 *   3. Generate a fresh key share for `selected_group`.
 *   4. Rebuild the ClientHello with the new key share and the echoed cookie.
 *   5. Read the *real* ServerHello that follows.
 *
 * The transcript hash after HRR is:
 *
 * ```
 * Transcript-Hash(ClientHello1, HelloRetryRequest, … Mn) =
 *     Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1) ||
 *          HelloRetryRequest || … || Mn)
 * ```
 *
 * This module owns the sentinel constant, the detection predicate, the HRR
 * extension parser, and the synthetic `message_hash` message builder — all pure
 * functions over their inputs, so they are independently unit-testable.
 */

import type { NamedGroup } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { ExtensionType, findExtension, parseExtensions, wireToNamedGroup } from "../extensions/extensions.js";
import { HandshakeType } from "./handshake-types.js";
import { constantTimeEqual } from "../utils.js";

/**
 * The 32-byte sentinel that distinguishes a HelloRetryRequest from a regular
 * ServerHello (RFC 8446 §4.1.3). A server MUST NOT send this value as the
 * `random` field of a genuine ServerHello.
 */
export const HELLO_RETRY_REQUEST_RANDOM = new Uint8Array([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

/**
 * Test whether a ServerHello `random` field is the HRR sentinel.
 *
 * Uses constant-time comparison so a timing oracle cannot distinguish HRR
 * detection from a normal ServerHello — matching the security posture of the
 * downgrade sentinel check in `server-hello.ts`.
 */
export function isHelloRetryRequest(random: Uint8Array): boolean {
    return constantTimeEqual(random, HELLO_RETRY_REQUEST_RANDOM);
}

/**
 * The extensions parsed from a HelloRetryRequest.
 *
 * `selectedGroup` comes from the HRR `key_share` extension (which carries only
 * the 2-byte group identifier — no key-exchange data, unlike a real ServerHello).
 * `cookie` is optional (RFC 8446 §4.2.2): the client MUST echo it back in the
 * new ClientHello if present.
 */
export interface HelloRetryRequestExtensions {
    /** The (EC)DHE group the server requests the client to generate a key share for. */
    readonly selectedGroup: NamedGroup;
    /** The anti-DoS cookie, if the server included one (RFC 8446 §4.2.2). */
    readonly cookie?: Uint8Array;
}

/**
 * Parse the extensions from an HRR ServerHello.
 *
 * The input is the raw extensions block (including the 2-byte length prefix)
 * from the parsed ServerHello — the same `extensions` field the caller already
 * has from `parseServerHello`.
 *
 * Throws {@link TlsHandshakeError} with phase `"server_hello"` if the required
 * `key_share` extension with `selected_group` is missing or malformed.
 */
export function parseHelloRetryRequestExtensions(extensions: Uint8Array): HelloRetryRequestExtensions {
    const parsed = parseExtensions(extensions);

    // key_share in HRR: exactly 2 bytes — the selected_group (no key data).
    const keyShare = findExtension(parsed, ExtensionType.KEY_SHARE);
    if (keyShare === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("HelloRetryRequest missing required key_share extension"),
        });
    }
    if (keyShare.data.length !== 2) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(
                `HelloRetryRequest key_share extension must be exactly 2 bytes (selected_group), got ${keyShare.data.length}`,
            ),
        });
    }
    const groupHi = keyShare.data[0];
    const groupLo = keyShare.data[1];
    if (groupHi === undefined || groupLo === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("HelloRetryRequest key_share data truncated"),
        });
    }
    const selectedGroup = wireToNamedGroup((groupHi << 8) | groupLo);

    // cookie extension is optional (RFC 8446 §4.2.2).
    const cookieExt = findExtension(parsed, ExtensionType.COOKIE);
    if (cookieExt !== undefined) {
        // cookie body: cookie_length(2) || cookie. Extract the raw cookie bytes
        // so the client can echo them in the new ClientHello without re-parsing.
        const cookie = extractCookieValue(cookieExt.data);
        return { selectedGroup, cookie };
    }
    return { selectedGroup };
}

/**
 * Extract the raw cookie bytes from a cookie extension body.
 *
 * The wire layout is `cookie_length(2) || cookie` (RFC 8446 §4.2.2). The
 * returned slice is what the client must echo in its new ClientHello's cookie
 * extension body (which has the same `cookie_length(2) || cookie` layout).
 */
function extractCookieValue(cookieBody: Uint8Array): Uint8Array {
    if (cookieBody.length < 2) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("HelloRetryRequest cookie extension too short for length prefix"),
        });
    }
    const lenHi = cookieBody[0];
    const lenLo = cookieBody[1];
    if (lenHi === undefined || lenLo === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("HelloRetryRequest cookie length prefix truncated"),
        });
    }
    const cookieLen = (lenHi << 8) | lenLo;
    if (2 + cookieLen !== cookieBody.length) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("HelloRetryRequest cookie length does not match extension body size"),
        });
    }
    return cookieBody.subarray(2, 2 + cookieLen);
}

/**
 * Build the synthetic `message_hash` handshake message for the transcript
 * (RFC 8446 §4.4.1).
 *
 * When an HRR is received, the transcript is rewritten to start with:
 *
 * ```
 * HandshakeType.message_hash(254) || length(3) || Hash(ClientHello_1)
 * ```
 *
 * This replaces `ClientHello_1` itself in the transcript — the original message
 * bytes are no longer hashed directly; only their hash is. This is what makes
 * the transcript hash after HRR different from the no-HRR case, and getting it
 * byte-exact is critical for the key schedule.
 *
 * @param hashValue  `Hash(ClientHello_1)` — the transcript hash of the original
 *                    ClientHello, computed with the negotiated cipher's hash.
 */
export function buildMessageHashMessage(hashValue: Uint8Array): Uint8Array {
    const message = new Uint8Array(4 + hashValue.length);
    message[0] = HandshakeType.MESSAGE_HASH; // 254
    message[1] = (hashValue.length >> 16) & 0xff;
    message[2] = (hashValue.length >> 8) & 0xff;
    message[3] = hashValue.length & 0xff;
    message.set(hashValue, 4);
    return message;
}
