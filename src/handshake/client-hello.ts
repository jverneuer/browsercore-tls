/**
 * ClientHello construction (RFC 8446 §4.2).
 *
 * Serializes the client's opening handshake message: legacy version + random +
 * session id + cipher suites + the extensions that actually drive TLS 1.3
 * negotiation (SNI, supported_versions, key_share, signature_algorithms, ALPN).
 * This is the only place that knows the ClientHello wire layout; the rest of the
 * handshake module only consumes the bytes it produces.
 */

import { crypto } from "@browsercore/crypto";
import type {
    CipherSuite,
    ClientHelloConfig,
    KeyPair,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
} from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { assertNever } from "../utils.js";
import { ExtensionType, namedGroupToWire, signatureSchemeToWire } from "../extensions/extensions.js";
import { HandshakeType } from "./handshake-types.js";

/** TLS 1.2 wire version used as legacy_version in TLS 1.3 records/handshakes. */
const TLS_1_2_WIRE_VERSION = 0x0303;

/**
 * GREASE (RFC 8701) reserved cipher-suite sentinel. Real browsers randomize the
 * exact 0x?a?a value per-connection; we use the canonical first GREASE code.
 */
const GREASE_CIPHER_WIRE = 0x0a0a;

/** GREASE extension-type sentinel (0x0a0a). */
const GREASE_EXTENSION_WIRE = 0x0a0a;

/**
 * Length (bytes) of the key-exchange blob we emit for a GREASE key-share entry.
 * Matches X25519 so the GREASE entry is indistinguishable in size from a real one.
 */
const GREASE_KEY_LENGTH = 32;

/**
 * Cipher suite IANA wire values.
 *
 * Covers every suite the shipped browser profiles offer: the four TLS 1.3 AEAD
 * suites (the only ones a TLS 1.3 handshake can *negotiate*) plus the TLS 1.2
 * suites and the GREASE placeholder that real Chrome places in the *offered*
 * ClientHello list for middlebox compatibility. Values come from the IANA TLS
 * Cipher Suite Registry and match `@browsercore/profiles`' canonical table.
 */
export function cipherSuiteToWire(suite: CipherSuite): number {
    switch (suite) {
        // GREASE sentinel (RFC 8701). Real value is randomized per-connection.
        case "TLS_GREASE_RESERVED_0":
            return GREASE_CIPHER_WIRE;
        // TLS 1.3 AEAD suites (the only ones this client can negotiate).
        case "TLS_AES_128_GCM_SHA256":
            return 0x1301;
        case "TLS_AES_256_GCM_SHA384":
            return 0x1302;
        case "TLS_CHACHA20_POLY1305_SHA256":
            return 0x1303;
        case "TLS_AES_128_CCM_SHA256":
            return 0x1304;
        // TLS 1.2 ECDHE/GCM suites.
        case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
            return 0xc02b;
        case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
            return 0xc02f;
        case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
            return 0xc02c;
        case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
            return 0xc030;
        case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
            return 0xcca9;
        case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
            return 0xcca8;
        // TLS 1.2 ECDHE/CBC suites.
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
            return 0xc013;
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
            return 0xc014;
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
            return 0xc009;
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
            return 0xc00a;
        // TLS 1.2 RSA suites.
        case "TLS_RSA_WITH_AES_128_GCM_SHA256":
            return 0x009c;
        case "TLS_RSA_WITH_AES_256_GCM_SHA384":
            return 0x009d;
        case "TLS_RSA_WITH_AES_128_CBC_SHA":
            return 0x002f;
        case "TLS_RSA_WITH_AES_256_CBC_SHA":
            return 0x0035;
        // TLS 1.2 CBC/SHA256 suites (Safari legacy tail).
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
            return 0xc023;
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
            return 0xc027;
        case "TLS_RSA_WITH_AES_128_CBC_SHA256":
            return 0x003c;
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":
            return 0xc024;
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":
            return 0xc028;
        case "TLS_RSA_WITH_AES_256_CBC_SHA256":
            return 0x003d;
        // TLS 1.2 3DES suites (Safari legacy tail — BoringSSL dropped these,
        // curl-impersonate restores them so Safari\'s ClientHello matches byte-for-byte).
        case "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":
            return 0xc008;
        case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
            return 0xc012;
        case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
            return 0x000a;
        default:
            // Every CipherSuite member is covered above; this is unreachable but
            // keeps the switch exhaustive if the union is ever extended.
            return assertNever(suite);
    }
}

/**
 * Canonical, exhaustive list of every cipher suite the shipped browser
 * profiles offer. Single source of truth — @browsercore/profiles imports this
 * instead of maintaining a duplicate table. Order mirrors IANA grouping, not
 * wire order (profiles define their own wire order).
 */
export const ALL_CIPHER_SUITES: readonly CipherSuite[] = [
    "TLS_GREASE_RESERVED_0",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
] as const;

/**
 * Type guard: true when `s` is a known CipherSuite. Profile authors use this to
 * validate a cipher name before casting.
 */
export function isCipherSuite(s: string): s is CipherSuite {
    return (ALL_CIPHER_SUITES as readonly string[]).includes(s);
}

/**
 * Build a ClientHello handshake message from the given config.
 *
 * Serializes the full handshake message (header + body) with extensions for SNI,
 * supported_versions, key_share, signature_algorithms, and (optionally) ALPN.
 * The (EC)DHE public keys come from `keyPairs` (already generated by the caller
 * via @browsercore/crypto).
 */
export function buildClientHello(config: ClientHelloConfig, keyPairs: readonly KeyPair[]): Uint8Array {
    const random = crypto.randomBytes(32);
    const sessionId = new Uint8Array(0);
    const compressionMethods = new Uint8Array([0x00]);

    const extensions = buildClientHelloExtensions(config, keyPairs);

    // Body length: version(2) + random(32) + session_id_len(1) + session_id +
    //   cipher_suites_len(2) + cipher_suites + compression_len(1) + compression +
    //   extensions_len(2) + extensions.
    //
    // Map every offered cipher suite to its 2-byte IANA wire value. The profile
    // data encodes GREASE positions via the TLS_GREASE_RESERVED_0 placeholder,
    // which maps to 0x0a0a. As a safety net, when grease is enabled we ensure a
    // GREASE sentinel leads the list even if the profile omitted the placeholder.
    const cipherWires: number[] = config.cipherSuites.map((suite, i) => {
        if (suite === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`cipher suite at index ${i} is missing`),
            });
        }
        return cipherSuiteToWire(suite);
    });
    if (config.grease && (cipherWires.length === 0 || cipherWires[0] !== GREASE_CIPHER_WIRE)) {
        cipherWires.unshift(GREASE_CIPHER_WIRE);
    }
    const cipherSuitesBytes = new Uint8Array(cipherWires.length * 2);
    for (let i = 0; i < cipherWires.length; i++) {
        const wire = cipherWires[i];
        if (wire === undefined) {
            // cipherWires.length bounds this loop, so this is unreachable — but
            // noUncheckedIndexedAccess can't prove it, so read through a local.
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`cipher suite wire at index ${i} is missing`),
            });
        }
        cipherSuitesBytes[i * 2] = (wire >> 8) & 0xff;
        cipherSuitesBytes[i * 2 + 1] = wire & 0xff;
    }

    const bodyLen =
        2 + random.length + 1 + sessionId.length +
        2 + cipherSuitesBytes.length +
        1 + compressionMethods.length +
        2 + extensions.length;

    // Handshake header: msg_type(1) + length(24-bit) + body.
    const message = new Uint8Array(1 + 3 + bodyLen);
    let o = 0;
    message[o++] = HandshakeType.CLIENT_HELLO;
    message[o++] = (bodyLen >> 16) & 0xff;
    message[o++] = (bodyLen >> 8) & 0xff;
    message[o++] = bodyLen & 0xff;

    // legacy_version = 0x0303 (TLS 1.2 for middlebox compatibility).
    message[o++] = (TLS_1_2_WIRE_VERSION >> 8) & 0xff;
    message[o++] = TLS_1_2_WIRE_VERSION & 0xff;
    message.set(random, o);
    o += random.length;

    // Session ID (length-prefixed; empty for TLS 1.3).
    message[o++] = sessionId.length & 0xff;
    message.set(sessionId, o);
    o += sessionId.length;

    // Cipher suites (length-prefixed).
    message[o++] = (cipherSuitesBytes.length >> 8) & 0xff;
    message[o++] = cipherSuitesBytes.length & 0xff;
    message.set(cipherSuitesBytes, o);
    o += cipherSuitesBytes.length;

    // Compression methods (length-prefixed; single null).
    message[o++] = compressionMethods.length & 0xff;
    message.set(compressionMethods, o);
    o += compressionMethods.length;

    // Extensions (length-prefixed).
    message[o++] = (extensions.length >> 8) & 0xff;
    message[o++] = extensions.length & 0xff;
    message.set(extensions, o);

    return message;
}

/**
 * Serialize the extensions block for a ClientHello. Each extension is
 * type(2) || data_len(2) || data, all under a single length-prefix.
 *
 * Extensions are emitted in the exact order given by `config.extensionOrder`,
 * which is the primary TLS fingerprinting signal. Every type the profile lists
 * must have a matching encoder; an unknown type is a bug in the profile data
 * and fails fast rather than emitting a malformed/omitted extension.
 *
 * When GREASE is enabled, a GREASE extension (type 0x0a0a, empty body) is
 * prepended ahead of the profile's order, matching real-browser behavior.
 */
function buildClientHelloExtensions(config: ClientHelloConfig, keyPairs: readonly KeyPair[]): Uint8Array {
    const order = config.grease
        ? [GREASE_EXTENSION_WIRE, ...config.extensionOrder]
        : [...config.extensionOrder];

    const parts: Uint8Array[] = [];
    for (const type of order) {
        const body = encodeExtensionBody(type, config, keyPairs);
        parts.push(wrapExtension(type, body));
    }

    let total = 0;
    for (const p of parts) {
        total += p.length;
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

/**
 * Dispatch an extension type to its body encoder. Centralizes the type→encoder
 * mapping so the emission loop stays a thin iteration over the profile order.
 */
function encodeExtensionBody(type: number, config: ClientHelloConfig, keyPairs: readonly KeyPair[]): Uint8Array {
    switch (type) {
        case ExtensionType.SERVER_NAME:
            return encodeServerNameList(config.serverName);
        case ExtensionType.STATUS_REQUEST:
            return encodeStatusRequest();
        case ExtensionType.SUPPORTED_GROUPS:
            return encodeSupportedGroups(config.keyShareGroups);
        case ExtensionType.EC_POINT_FORMATS:
            return encodeEcPointFormats();
        case ExtensionType.SIGNATURE_ALGORITHMS:
            return encodeSignatureAlgorithms(config.signatureAlgorithms);
        case ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            // ALPN is only meaningful when the client actually offers protocols.
            return config.alpnProtocols !== undefined && config.alpnProtocols.length > 0
                ? encodeAlpn(config.alpnProtocols)
                : new Uint8Array(0);
        case ExtensionType.APPLICATION_SETTINGS:
            return encodeApplicationSettings(config.alpnProtocols);
        case ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP:
            return new Uint8Array(0);
        case ExtensionType.EXTENDED_MASTER_SECRET:
            return new Uint8Array(0);
        case ExtensionType.COMPRESS_CERTIFICATE:
            return encodeCompressCertificate();
        case ExtensionType.SESSION_TICKET:
            return new Uint8Array(0);
        case ExtensionType.PRE_SHARED_KEY:
            return new Uint8Array(0);
        case ExtensionType.SUPPORTED_VERSIONS:
            return encodeSupportedVersionsClient(config.supportedVersions);
        case ExtensionType.PSK_KEY_EXCHANGE_MODES:
            return encodePskKeyExchangeModes();
        case ExtensionType.KEY_SHARE:
            return encodeKeyShareClient(config, keyPairs);
        case ExtensionType.RENEGOTIATION_INFO:
            return encodeRenegotiationInfo();
        default:
            // A GREASE extension (0x?a?a) or any other type without a body
            // encoder is emitted with an empty body — exactly what real browsers
            // do for GREASE values.
            if (isGreaseValue(type)) {
                return new Uint8Array(0);
            }
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`no encoder for extension type 0x${type.toString(16)}`),
            });
    }
}

/**
 * A GREASE value follows the 0x?a?a pattern (byte 0x? a repeated), per RFC 8701.
 * Both bytes are identical and each byte's low nibble is 0xa.
 */
function isGreaseValue(type: number): boolean {
    const hi = (type >> 8) & 0xff;
    const lo = type & 0xff;
    return type > 0 && hi === lo && (lo & 0x0f) === 0x0a;
}

/** Encode the supported_groups extension body (RFC 8446 §4.2.7). */
function encodeSupportedGroups(groups: readonly NamedGroup[]): Uint8Array {
    const out = new Uint8Array(2 + groups.length * 2);
    out[0] = ((groups.length * 2) >> 8) & 0xff;
    out[1] = (groups.length * 2) & 0xff;
    for (let i = 0; i < groups.length; i++) {
        const group = groups[i];
        if (group === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`supported group at index ${i} is missing`),
            });
        }
        const wire = namedGroupToWire(group);
        out[2 + i * 2] = (wire >> 8) & 0xff;
        out[2 + i * 2 + 1] = wire & 0xff;
    }
    return out;
}

/**
 * Encode the ec_point_formats extension body (RFC 4492 §5.1). Chrome sends only
 * uncompressed (0x00).
 */
function encodeEcPointFormats(): Uint8Array {
    return new Uint8Array([0x01, 0x00]);
}

/**
 * Encode the application_settings (ALPN) extension body (RFC 8441). Carries the
 * same protocol list as ALPN. Defaults to "h2" when no ALPN protocols are set.
 */
function encodeApplicationSettings(alpnProtocols: readonly string[] | undefined): Uint8Array {
    const protocols = alpnProtocols !== undefined && alpnProtocols.length > 0 ? alpnProtocols : ["h2"];
    return encodeAlpn(protocols);
}

/**
 * Encode the compress_certificate extension body (RFC 8879 §3). Chrome 140
 * advertises zlib (0x0001), brotli (0x0002), and zstd (0x0003).
 */
function encodeCompressCertificate(): Uint8Array {
    const algorithms = [0x0001, 0x0002, 0x0003];
    const out = new Uint8Array(1 + algorithms.length * 2);
    out[0] = (algorithms.length * 2) & 0xff;
    for (let i = 0; i < algorithms.length; i++) {
        const algo = algorithms[i];
        if (algo === undefined) {
            // algorithms.length bounds this loop, so this is unreachable.
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`compress certificate algorithm at index ${i} is missing`),
            });
        }
        out[1 + i * 2] = (algo >> 8) & 0xff;
        out[1 + i * 2 + 1] = algo & 0xff;
    }
    return out;
}

/** Encode the psk_key_exchange_modes extension body (RFC 8446 §4.2.9). */
function encodePskKeyExchangeModes(): Uint8Array {
    // psk_dhe_ke (1) is the only mode TLS 1.3 resumption uses.
    return new Uint8Array([0x01, 0x01]);
}

/** Encode the status_request extension body (RFC 6066 §8) — OCSP only. */
function encodeStatusRequest(): Uint8Array {
    // status_type=1 (OCSP) + empty responder_id_list + empty request_extensions.
    return new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00]);
}

/** Encode the renegotiation_info extension body (RFC 5746 §3.2). */
function encodeRenegotiationInfo(): Uint8Array {
    // renegotiated_connection length = 0 (no renegotiation in progress).
    return new Uint8Array([0x00]);
}

/**
 * Wrap an extension body with its type + length prefix.
 *
 * Accepts a raw `number` (not just the `ExtensionType` union) so GREASE
 * extension types (0x?a?a) and any future type can be emitted without a cast.
 */
function wrapExtension(type: number, data: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + 2 + data.length);
    out[0] = (type >> 8) & 0xff;
    out[1] = type & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out[3] = data.length & 0xff;
    out.set(data, 4);
    return out;
}

/** Encode the SNI server_name_list body (RFC 6066 §3). */
function encodeServerNameList(serverName: string): Uint8Array {
    const nameBytes = new TextEncoder().encode(serverName);
    if (nameBytes.length > 0xffff) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("SNI server_name exceeds 65535 bytes"),
        });
    }
    // server_name_list: length(2) + entries. Each entry: type(1)=0 + length(2) + name.
    const entry = new Uint8Array(1 + 2 + nameBytes.length);
    entry[0] = 0; // host_name
    entry[1] = (nameBytes.length >> 8) & 0xff;
    entry[2] = nameBytes.length & 0xff;
    entry.set(nameBytes, 3);

    const out = new Uint8Array(2 + entry.length);
    out[0] = (entry.length >> 8) & 0xff;
    out[1] = entry.length & 0xff;
    out.set(entry, 2);
    return out;
}

/** Encode the supported_versions extension body for the client (RFC 8446 §4.2.1). */
function encodeSupportedVersionsClient(versions: readonly ProtocolVersion[]): Uint8Array {
    const out = new Uint8Array(1 + versions.length * 2);
    out[0] = (versions.length * 2) & 0xff;
    for (let i = 0; i < versions.length; i++) {
        const version = versions[i];
        if (version === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`supported version at index ${i} is missing`),
            });
        }
        const wire = version.wire;
        out[1 + i * 2] = (wire >> 8) & 0xff;
        out[1 + i * 2 + 1] = wire & 0xff;
    }
    return out;
}

/**
 * Encode the key_share extension body for the client (RFC 8446 §4.2.8).
 *
 * When GREASE is enabled, a GREASE key-share entry (group 0x0a0a) with a random
 * key precedes the real groups — matching real-browser ClientHellos.
 */
function encodeKeyShareClient(config: ClientHelloConfig, keyPairs: readonly KeyPair[]): Uint8Array {
    // client_shares: length(2) + entries. Each: group(2) + len(2) + key_exchange.
    const greaseEntry = config.grease ? 2 + 2 + GREASE_KEY_LENGTH : 0;
    let entriesLen = greaseEntry;
    for (const kp of keyPairs) {
        entriesLen += 2 + 2 + kp.publicKey.length;
    }
    const out = new Uint8Array(2 + entriesLen);
    out[0] = (entriesLen >> 8) & 0xff;
    out[1] = entriesLen & 0xff;
    let o = 2;
    if (config.grease) {
        // GREASE key-share group (0x0a0a) with a random key of GREASE_KEY_LENGTH bytes.
        out[o++] = (GREASE_CIPHER_WIRE >> 8) & 0xff;
        out[o++] = GREASE_CIPHER_WIRE & 0xff;
        out[o++] = (GREASE_KEY_LENGTH >> 8) & 0xff;
        out[o++] = GREASE_KEY_LENGTH & 0xff;
        out.set(crypto.randomBytes(GREASE_KEY_LENGTH), o);
        o += GREASE_KEY_LENGTH;
    }
    for (const kp of keyPairs) {
        const groupWire = namedGroupToWire(kp.algorithm);
        out[o++] = (groupWire >> 8) & 0xff;
        out[o++] = groupWire & 0xff;
        out[o++] = (kp.publicKey.length >> 8) & 0xff;
        out[o++] = kp.publicKey.length & 0xff;
        out.set(kp.publicKey, o);
        o += kp.publicKey.length;
    }
    return out;
}

/** Encode the signature_algorithms extension body (RFC 8446 §4.2.3). */
function encodeSignatureAlgorithms(algorithms: readonly SignatureScheme[]): Uint8Array {
    const out = new Uint8Array(2 + algorithms.length * 2);
    out[0] = ((algorithms.length * 2) >> 8) & 0xff;
    out[1] = (algorithms.length * 2) & 0xff;
    for (let i = 0; i < algorithms.length; i++) {
        const scheme = algorithms[i];
        if (scheme === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`signature algorithm at index ${i} is missing`),
            });
        }
        const wire = signatureSchemeToWire(scheme);
        out[2 + i * 2] = (wire >> 8) & 0xff;
        out[2 + i * 2 + 1] = wire & 0xff;
    }
    return out;
}

/** Encode the ALPN extension body (RFC 7301). */
function encodeAlpn(protocols: readonly string[]): Uint8Array {
    let entriesLen = 0;
    for (const proto of protocols) {
        const encoded = new TextEncoder().encode(proto);
        if (encoded.length === 0 || encoded.length > 0xff) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`ALPN protocol must be 1..255 bytes: "${proto}"`),
            });
        }
        entriesLen += 1 + encoded.length;
    }
    const out = new Uint8Array(2 + entriesLen);
    out[0] = (entriesLen >> 8) & 0xff;
    out[1] = entriesLen & 0xff;
    let o = 2;
    for (const proto of protocols) {
        const encoded = new TextEncoder().encode(proto);
        out[o++] = encoded.length & 0xff;
        out.set(encoded, o);
        o += encoded.length;
    }
    return out;
}
