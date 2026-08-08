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
        // Common TLS 1.2 cipher suites (IANA). The client only speaks TLS 1.3,
        // so a server negotiating any of these is a protocol downgrade — surface
        // a clear, actionable error instead of the cryptic "unsupported" message.
        case 0x002f: case 0x0035: case 0x003c: case 0x003d: case 0x009c: case 0x009d:
        case 0xc007: case 0xc008: case 0xc009: case 0xc00a: case 0xc011: case 0xc012:
        case 0xc013: case 0xc014: case 0xc023: case 0xc024: case 0xc027: case 0xc028:
        case 0xc02b: case 0xc02c: case 0xc02f: case 0xc030: case 0xcca8: case 0xcca9:
        case 0xccaa: case 0x0004: case 0x0005: case 0x000a: case 0x0009: case 0x0016:
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(
                    `server negotiated TLS 1.2 cipher suite 0x${wire.toString(16)} ` +
                    `— the client only speaks TLS 1.3. ` +
                    `Use a server that supports TLS 1.3.`,
                ),
            });
        default:
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
