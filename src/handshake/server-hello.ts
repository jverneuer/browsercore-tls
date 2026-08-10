/**
 * ServerHello parsing and version negotiation (RFC 8446 §4.2.1).
 *
 * Decodes the server's ServerHello and validates it against what the client
 * offered — the selected cipher suite must be one we advertised, and the
 * negotiated version (from the supported_versions extension) must be one we
 * support. Failing fast here makes an unacceptable negotiation unrepresentable.
 */

import type { CipherSuite, ProtocolVersion } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { ExtensionType, findExtension, parseExtensions } from "../extensions/extensions.js";
import { assertCipherSuiteOffered, assertVersionSupported } from "../crypto/keySchedule.js";
import { constantTimeEqual } from "../utils.js";
import type { ServerHello } from "./handshake-types.js";

/**
 * What the client offered in its ClientHello, needed so the ServerHello can be
 * validated against it. Only the fields that {@link parseServerHello} checks are
 * required — everything else is irrelevant to ServerHello parsing.
 */
export interface ServerHelloValidation {
    /** Cipher suites the client advertised, most-preferred first. */
    readonly cipherSuites: readonly CipherSuite[];
    /** Protocol versions the client advertised via supported_versions. */
    readonly supportedVersions: readonly ProtocolVersion[];
}

/**
 * Common TLS 1.2 cipher suites (IANA registry). The client only speaks TLS 1.3,
 * so a server negotiating any of these is a protocol downgrade. Stored as a Set
 * for O(1) lookup instead of a 30-arm case statement (which would tank branch
 * coverage — each untested case arm is a separate branch in v8 coverage).
 */
const TLS12_CIPHER_SUITES: ReadonlySet<number> = new Set([
    0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d,
    0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012,
    0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028,
    0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
    0xccaa, 0x0004, 0x0005, 0x000a, 0x0009, 0x0016,
]);

/**
 * Downgrade sentinels in the last 8 bytes of ServerHello.random (RFC 8446
 * §4.1.3). A TLS 1.3 server MUST NOT set these; their presence means the
 * negotiating peer is a TLS 1.2 (or earlier) implementation that intentionally
 * inserted the sentinel to prevent downgrade attacks. If a client negotiating
 * TLS 1.3 sees them, it MUST abort with {@link TlsHandshakeError} — the server
 * is either buggy or malicious.
 *
 * - `DOWNGRD\x01` (`44 4F 57 4E 47 52 44 01`): TLS 1.2 downgrade sentinel
 * - `DOWNGRD\x00` (`44 4F 57 4E 47 52 44 00`): TLS 1.1 or below downgrade sentinel
 */
const DOWNGRADE_SENTINEL_TLS12 = new Uint8Array([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01]);
const DOWNGRADE_SENTINEL_TLS11 = new Uint8Array([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00]);

/**
 * Check the last 8 bytes of ServerHello.random for a downgrade sentinel
 * (RFC 8446 §4.1.3). Throws {@link TlsHandshakeError} with phase "server_hello"
 * if either sentinel is present — the client MUST abort with `illegal_parameter`.
 */
function checkDowngradeSentinel(random: Uint8Array): void {
    const tail = random.subarray(24, 32);
    if (
        constantTimeEqual(tail, DOWNGRADE_SENTINEL_TLS12) ||
        constantTimeEqual(tail, DOWNGRADE_SENTINEL_TLS11)
    ) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(
                "ServerHello.random contains a downgrade sentinel — the server is " +
                "attempting to negotiate TLS 1.2 or below in a TLS 1.3 handshake " +
                "(RFC 8446 §4.1.3 requires the client to abort with illegal_parameter)",
            ),
        });
    }
}

/** Invert the cipher-suite wire values; throws on unknown values. */
function wireToCipherSuite(wire: number): CipherSuite {
    switch (wire) {
        case 0x1301:
            return "TLS_AES_128_GCM_SHA256";
        case 0x1302:
            return "TLS_AES_256_GCM_SHA384";
        case 0x1303:
            return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x1304:
            return "TLS_AES_128_CCM_SHA256";
        default:
            // Common TLS 1.2 cipher suites (IANA). The client only speaks TLS 1.3,
            // so a server negotiating any of these is a protocol downgrade — surface
            // a clear, actionable error instead of the cryptic "unsupported" message.
            if (TLS12_CIPHER_SUITES.has(wire)) {
                throw new TlsHandshakeError("server_hello", {
                    cause: new Error(
                        `server negotiated TLS 1.2 cipher suite 0x${wire.toString(16)} ` +
                        `— the client only speaks TLS 1.3. ` +
                        `Use a server that supports TLS 1.3.`,
                    ),
                });
            }
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`unsupported cipher suite wire value: 0x${wire.toString(16)}`),
            });
    }
}

/**
 * Map a 16-bit wire version to the branded {@link ProtocolVersion} from the
 * offered list. Throws if the server selected a version we did not offer.
 */
function selectVersion(wire: number, offered: readonly ProtocolVersion[]): ProtocolVersion {
    for (const version of offered) {
        if (version.wire === wire) {
            return version;
        }
    }
    throw new TlsHandshakeError("server_hello", {
        cause: new Error(`server negotiated version we did not offer: 0x${wire.toString(16)}`),
    });
}

/**
 * Parse a ServerHello from a handshake message body (without the 4-byte handshake header).
 *
 * Validates that the selected cipher suite was actually offered and that the
 * negotiated protocol version (from the supported_versions extension) is one we
 * support — failing fast makes an unacceptable negotiation unrepresentable.
 *
 * Throws {@link TlsHandshakeError} with phase "server_hello" on malformed input
 * or a failed validation.
 */
export function parseServerHello(buf: Uint8Array, offered: ServerHelloValidation): ServerHello {
    let o = 0;
    const expect = (n: number): void => {
        if (o + n > buf.length) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`ServerHello truncated at offset ${o} (need ${n}, have ${buf.length - o})`),
            });
        }
    };
    const readByte = (): number => {
        expect(1);
        const byte = buf[o];
        if (byte === undefined) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`ServerHello byte truncated at offset ${o}`),
            });
        }
        o++;
        return byte;
    };

    expect(2 + 32 + 1);
    const protocolVersion = (readByte() << 8) | readByte();
    const random = buf.subarray(o, o + 32);
    o += 32;

    // RFC 8446 §4.1.3: check the last 8 bytes of ServerHello.random for a
    // downgrade sentinel. A TLS 1.3 server MUST NOT set these — their presence
    // means the peer is actually TLS 1.2 or below, and the client MUST abort.
    checkDowngradeSentinel(random);

    const sessionIdLen = readByte();
    expect(sessionIdLen);
    const sessionId = buf.subarray(o, o + sessionIdLen);
    o += sessionIdLen;

    expect(2 + 1 + 2);
    const cipherSuiteWire = (readByte() << 8) | readByte();
    const cipherSuite = wireToCipherSuite(cipherSuiteWire);
    const compressionMethod = readByte();
    if (compressionMethod !== 0x00) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`unsupported compression method: ${compressionMethod}`),
        });
    }

    // The server MUST negotiate a cipher suite we offered.
    assertCipherSuiteOffered(cipherSuite, offered.cipherSuites);

    // Capture the offset before reading extensions_len so the slice retains the
    // 2-byte length prefix. parseExtensions (used both here for the
    // supported_versions extension and later by the key-share extraction in
    // _computeSharedSecret) requires its input to be the length-prefixed block.
    const extensionsStart = o;
    const extensionsLen = (readByte() << 8) | readByte();
    expect(extensionsLen);
    const extensions = buf.subarray(extensionsStart, o + extensionsLen);

    const selectedVersion = negotiateVersion(extensions, offered.supportedVersions);

    void protocolVersion;
    return { protocolVersion, random, sessionId, cipherSuite, compressionMethod, selectedVersion, extensions };
}

/**
 * Extract the version the server negotiated from the supported_versions
 * extension (RFC 8446 §4.2.1) and validate it. The server's extension body is a
 * single uint16 — the one version it selected from our offered list.
 */
function negotiateVersion(extensionsRaw: Uint8Array, offered: readonly ProtocolVersion[]): ProtocolVersion {
    const extensions = parseExtensions(extensionsRaw);
    const sv = findExtension(extensions, ExtensionType.SUPPORTED_VERSIONS);
    if (sv === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("ServerHello missing required supported_versions extension"),
        });
    }
    if (sv.data.length !== 2) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`supported_versions extension has unexpected length ${sv.data.length}`),
        });
    }
    const hi = sv.data[0];
    const lo = sv.data[1];
    if (hi === undefined || lo === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`supported_versions extension data truncated`),
        });
    }
    const wire = (hi << 8) | lo;
    const selected = selectVersion(wire, offered);
    assertVersionSupported(selected);
    return selected;
}
