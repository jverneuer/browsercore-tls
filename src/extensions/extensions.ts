/**
 * TLS extensions (RFC 8446 §4.2, RFC 6066).
 *
 * Types, builders, and parsers for the extensions used in ClientHello and
 * ServerHello. Serialization is pure layout; no crypto here.
 */

import type { NamedGroup, ProtocolVersion, SignatureScheme } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { assertNever } from "../utils.js";

/** TLS extension types, per IANA / RFC 8446. */
export const ExtensionType = {
    SERVER_NAME: 0,
    MAX_FRAGMENT_LENGTH: 1,
    SUPPORTED_GROUPS: 10,
    SIGNATURE_ALGORITHMS: 13,
    USE_SRTP: 14,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION: 16,
    COMPRESS_CERTIFICATE: 27,
    PRE_SHARED_KEY: 41,
    EARLY_DATA: 42,
    SUPPORTED_VERSIONS: 43,
    COOKIE: 44,
    PSK_KEY_EXCHANGE_MODES: 45,
    KEY_SHARE: 51,
    RENEGOTIATION_INFO: 65281,
} as const;

/** Union of valid extension-type values. */
export type ExtensionType = (typeof ExtensionType)[keyof typeof ExtensionType];

/** A generic TLS extension: type + opaque data. */
export interface TlsExtension {
    readonly type: ExtensionType;
    readonly data: Uint8Array;
}

/** Server Name Indication (RFC 6066 §3). */
export interface ServerNameList {
    readonly names: readonly { readonly type: 0; readonly name: string }[];
}

/** Supported Versions (RFC 8446 §4.2.1). */
export interface SupportedVersionsClient {
    readonly versions: readonly ProtocolVersion[];
}

/** Key Share (RFC 8446 §4.2.8). */
export interface KeyShareEntry {
    readonly group: NamedGroup;
    readonly keyExchange: Uint8Array;
}

/** Signature Algorithms (RFC 8446 §4.2.3). */
export interface SignatureAlgorithms {
    readonly algorithms: readonly SignatureScheme[];
}

/**
 * Parse the extensions block (a length-prefixed list) into typed TlsExtension records.
 * Throws {@link TlsHandshakeError} on malformed input.
 *
 * Layout: extensions_length(2) || extensions, where each extension is
 * type(2) || data_length(2) || data.
 */
export function parseExtensions(buf: Uint8Array): readonly TlsExtension[] {
    if (buf.length < 2) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`extensions block too short: ${buf.length} < 2`),
        });
    }
    let o = 0;
    const readByte = (): number => {
        const byte = buf[o];
        if (byte === undefined) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`extension byte truncated at offset ${o}`),
            });
        }
        o++;
        return byte;
    };
    const extensionsLen = (readByte() << 8) | readByte();
    if (o + extensionsLen > buf.length) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`extensions length ${extensionsLen} exceeds buffer ${buf.length - o}`),
        });
    }
    const end = o + extensionsLen;
    const extensions: TlsExtension[] = [];
    while (o < end) {
        if (o + 4 > end) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`extension header truncated at offset ${o}`),
            });
        }
        const type = (readByte() << 8) | readByte();
        const dataLen = (readByte() << 8) | readByte();
        if (o + dataLen > end) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`extension data truncated: type=${type} len=${dataLen} at ${o}`),
            });
        }
        const data = buf.subarray(o, o + dataLen);
        o += dataLen;
        extensions.push({ type: wireToExtensionType(type), data });
    }
    return extensions;
}

/** Find the first extension of a given type, or undefined if absent. */
export function findExtension(
    extensions: readonly TlsExtension[],
    type: ExtensionType,
): TlsExtension | undefined {
    return extensions.find((ext) => ext.type === type);
}

/** IANA wire value for a signature scheme (subset). */
export function signatureSchemeToWire(scheme: SignatureScheme): number {
    switch (scheme) {
        case "ecdsa_secp256r1_sha256":
            return 0x0403;
        case "ecdsa_secp384r1_sha384":
            return 0x0503;
        case "rsa_pss_rsae_sha256":
            return 0x0804;
        case "rsa_pss_rsae_sha384":
            return 0x0805;
        case "rsa_pkcs1_sha256":
            return 0x0401;
        default:
            return assertNever(scheme);
    }
}

/** IANA wire value for a named group (subset). */
export function namedGroupToWire(group: NamedGroup): number {
    switch (group) {
        case "secp256r1":
            return 0x0017;
        case "secp384r1":
            return 0x0018;
        case "x25519":
            return 0x001d;
        case "x448":
            return 0x001e;
        default:
            return assertNever(group);
    }
}

/** Invert {@link namedGroupToWire}; throws {@link TlsHandshakeError} on unknown values. */
export function wireToNamedGroup(wire: number): NamedGroup {
    switch (wire) {
        case 0x0017:
            return "secp256r1";
        case 0x0018:
            return "secp384r1";
        case 0x001d:
            return "x25519";
        case 0x001e:
            return "x448";
        default:
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`unsupported named group wire value: 0x${wire.toString(16)}`),
            });
    }
}

/**
 * Validate a raw uint16 as a known {@link ExtensionType}.
 *
 * Replaces the previous `type as ExtensionType` cast that pretended any number
 * was a member of the union. Like {@link wireToNamedGroup}, this fails fast and
 * typed on an unrecognised value instead of smuggling an invalid type through
 * the type system.
 */
export function wireToExtensionType(wire: number): ExtensionType {
    switch (wire) {
        case ExtensionType.SERVER_NAME:
        case ExtensionType.MAX_FRAGMENT_LENGTH:
        case ExtensionType.SUPPORTED_GROUPS:
        case ExtensionType.SIGNATURE_ALGORITHMS:
        case ExtensionType.USE_SRTP:
        case ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
        case ExtensionType.COMPRESS_CERTIFICATE:
        case ExtensionType.PRE_SHARED_KEY:
        case ExtensionType.EARLY_DATA:
        case ExtensionType.SUPPORTED_VERSIONS:
        case ExtensionType.COOKIE:
        case ExtensionType.PSK_KEY_EXCHANGE_MODES:
        case ExtensionType.KEY_SHARE:
        case ExtensionType.RENEGOTIATION_INFO:
            return wire;
        default:
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`unsupported extension type wire value: 0x${wire.toString(16)}`),
            });
    }
}

