/**
 * ClientHello construction (RFC 8446 §4.2).
 *
 * Serializes the client's opening handshake message: legacy version + random +
 * session id + cipher suites + the extensions that actually drive TLS 1.3
 * negotiation (SNI, supported_versions, key_share, signature_algorithms, ALPN).
 * This is the only place that knows the ClientHello wire layout; the rest of the
 * handshake module only consumes the bytes it produces.
 */

import type { CryptoProvider } from "@browsercore/crypto";
import type {
    CipherSuite,
    ClientHelloConfig,
    KeyPair,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
} from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { ExtensionType, isGreaseValue, namedGroupToWire, signatureSchemeToWire } from "../extensions/extensions.js";
export { isGreaseValue } from "../extensions/extensions.js";
import { HandshakeType } from "./handshake-types.js";
import { CIPHER_SUITE_CODES } from "../iana/index.js";
import { computePaddingExtensionBody } from "../record/record-padding.js";

/** TLS 1.2 wire version used as legacy_version in TLS 1.3 records/handshakes. */
const TLS_1_2_WIRE_VERSION = 0x0303;

/**
 * The 16 GREASE sentinels reserved by RFC 8701 §2 (0x?a?a set).
 *
 * Real browsers draw each GREASE slot (cipher suite, extension type, key-share
 * group, …) INDEPENDENTLY and uniformly at random from this set — see the
 * golden chrome-131 capture, which shows cipher 0x5a5a, leading ext 0x4a4a,
 * key_share/supported_groups 0xcaca in a single ClientHello.
 * `generateGreaseValue` draws from here; `isGreaseValue` validates against it.
 * Single source of truth for the reserved set.
 */
export const GREASE_VALUES: readonly number[] = Object.freeze([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/**
 * Pick a uniform random GREASE value.
 *
 * The random source is a REQUIRED parameter (no singleton fallback) so the
 * caller — which already holds the injected CryptoProvider — controls every
 * source of randomness. Tests pin it deterministically; production passes a
 * crypto-backed uniform [0,1) so traffic never depends on Math.random.
 */
export function generateGreaseValue(random: () => number): number {
    const index = Math.floor(random() * GREASE_VALUES.length);
    const value = GREASE_VALUES[index];
    // GREASE_VALUES.length === 16 is a constant; this is an invariant guard.
    /* v8 ignore next 3 */
    if (value === undefined) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("generateGreaseValue: unreachable — GREASE_VALUES is empty"),
        });
    }
    return value;
}

/**
 * Length (bytes) of the key-exchange blob we emit for a GREASE key-share entry.
 *
 * Real Chrome sends a 1-byte zero payload — golden chrome-131 key_share opens
 * with `caca 0001 00` (group 0xcaca, key_length 1, one 0x00 byte), followed by
 * X25519MLKEM768 (1216B) and x25519 (32B). A 32-byte GREASE blob (the old
 * value) is a fingerprint divergence.
 */
const GREASE_KEY_LENGTH = 1;

/**
 * Payload byte for the GREASE key-share entry — real Chrome sends a literal
 * 0x00, not random bytes (see the golden chrome-131 capture).
 */
const GREASE_KEY_PAYLOAD = new Uint8Array([0x00]);

/**
 * The independent per-slot GREASE sentinels drawn for one ClientHello.
 *
 * Real Chrome draws each RFC 8701 slot independently rather than reusing one
 * value per connection (2026-11-15 fingerprint diagnosis, D7): the golden
 * chrome-131 capture shows cipher 0x5a5a, leading ext 0x4a4a,
 * supported_versions 0x4a4a, key_share + supported_groups 0xcaca, trailing ext
 * 0x5a5a — equalities between slots are per-capture coincidence, not structure.
 */
interface GreaseSentinels {
    /** GREASE cipher suite at the head of the offered list. */
    readonly cipherSuite: number;
    /** GREASE extension type prepended ahead of the profile's extension order. */
    readonly leadingExtension: number;
    /** GREASE group heading the key_share client_shares list. */
    readonly keyShareGroup: number;
    /** GREASE group heading the supported_groups list. */
    readonly supportedGroups: number;
    /** GREASE version heading the supported_versions list. */
    readonly supportedVersions: number;
    /** GREASE extension type appended as the absolute last extension. */
    readonly trailingExtension: number;
}

/**
 * Draw one independent sentinel per GREASE slot, in this order (the sequence is
 * a stable contract — tests pin it with a fake `random` to assert the exact
 * per-slot values that reach the wire).
 *
 * `trailingExtension` is redrawn until it differs from `leadingExtension`:
 * RFC 8446 §4.2 forbids duplicate extension types, so the two GREASE extension
 * SLOTS must never carry the same value. All other slots live in different
 * namespaces (cipher list, group lists, version list) and may repeat freely.
 */
function drawGreaseSentinels(random: () => number): GreaseSentinels {
    const cipherSuite = generateGreaseValue(random);
    const leadingExtension = generateGreaseValue(random);
    const keyShareGroup = generateGreaseValue(random);
    const supportedGroups = generateGreaseValue(random);
    const supportedVersions = generateGreaseValue(random);
    let trailingExtension = generateGreaseValue(random);
    for (let i = 0; i < 16 && trailingExtension === leadingExtension; i++) {
        trailingExtension = generateGreaseValue(random);
    }
    if (trailingExtension === leadingExtension) {
        // Deterministic escape from a stuck random source: step to the next
        // sentinel so the two extension slots never collide.
        const idx = GREASE_VALUES.indexOf(leadingExtension);
        /* v8 ignore next -- idx is always a valid GREASE_VALUES index; the guard only satisfies noUncheckedIndexedAccess */
        trailingExtension = GREASE_VALUES[(idx + 1) % GREASE_VALUES.length] ?? leadingExtension;
    }
    return { cipherSuite, leadingExtension, keyShareGroup, supportedGroups, supportedVersions, trailingExtension };
}

/**
 * Cipher suite IANA wire values.
 *
 * Covers every suite the shipped browser profiles offer: the four TLS 1.3 AEAD
 * suites (the only ones a TLS 1.3 handshake can *negotiate*) plus the TLS 1.2
 * suites and the GREASE placeholder that real Chrome places in the *offered*
 * ClientHello list for middlebox compatibility. Values come from the canonical
 * IANA table in `../iana/cipher-suites.ts`.
 */
export function cipherSuiteToWire(suite: CipherSuite): number {
    const code = CIPHER_SUITE_CODES[suite];
    if (code === undefined) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error(`unknown cipher suite: ${suite}`),
        });
    }
    return code;
}

/**
 * Build a ClientHello handshake message from the given config.
 *
 * Serializes the full handshake message (header + body) with extensions for SNI,
 * supported_versions, key_share, signature_algorithms, and (optionally) ALPN.
 * The (EC)DHE public keys come from `keyPairs` (already generated by the caller
 * via @browsercore/crypto).
 *
 * When `config.grease` is enabled, an INDEPENDENT random 0x?a?a sentinel is
 * drawn per slot (from `random`) — cipher list head, leading extension,
 * key-share group, supported_groups head, supported_versions head, trailing
 * extension — matching real Chrome, which draws each slot independently
 * (RFC 8701; golden chrome-131: cipher 0x5a5a, ext 0x4a4a, keyshare/groups
 * 0xcaca). The `random` source and `provider` are required (no singleton
 * fallback) so callers control all randomness; tests pin `random` for
 * deterministic sentinels.
 */
export function buildClientHello(
    config: ClientHelloConfig,
    keyPairs: readonly KeyPair[],
    random: () => number,
    provider: CryptoProvider,
    cookie?: Uint8Array,
): Uint8Array {
    const sentinels = config.grease ? drawGreaseSentinels(random) : undefined;

    const randomBytes = provider.randomBytes(32);
    const sessionId = provider.randomBytes(32);
    const compressionMethods = new Uint8Array([0x00]);

    const cipherWires: number[] = config.cipherSuites.map((suite, i) => {
        if (suite === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`cipher suite at index ${i} is missing`),
            });
        }
        return cipherSuiteToWire(suite);
    });
    if (cipherWires.length > 0 && sentinels !== undefined) {
        // The length guard above narrows the element to `number`, so this read
        // satisfies noUncheckedIndexedAccess without a non-null assertion.
        const first = cipherWires[0];
        if (first !== undefined && isGreaseValue(first)) {
            cipherWires[0] = sentinels.cipherSuite;
        } else {
            cipherWires.unshift(sentinels.cipherSuite);
        }
    }
    const cipherSuitesBytes = new Uint8Array(cipherWires.length * 2);
    for (let i = 0; i < cipherWires.length; i++) {
        const wire = cipherWires[i];
        /* v8 ignore next 3 */
        if (wire === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`cipher suite wire at index ${i} is missing`),
            });
        }
        cipherSuitesBytes[i * 2] = (wire >> 8) & 0xff;
        cipherSuitesBytes[i * 2 + 1] = wire & 0xff;
    }

    // Build base extensions (with zero padding) to measure the ClientHello size.
    // The GREASE sentinels are drawn once above so the probe and the padded
    // rebuild emit byte-identical sentinel values.
    const baseExtensions = buildClientHelloExtensions(config, keyPairs, sentinels, provider, cookie);

    // Record padding (RFC 7685 / RFC 8446 §4.1.2): measure the base ClientHello
    // (extensions built with zero padding), then rebuild with the computed
    // padding body so the total message hits `config.recordPadding` bytes.
    let finalExtensions = baseExtensions;
    if (config.recordPadding !== undefined) {
        const bodyLenProbe =
            2 + randomBytes.length + 1 + sessionId.length +
            2 + cipherSuitesBytes.length +
            1 + compressionMethods.length +
            2 + baseExtensions.length;
        const probeMessageSize = 4 + bodyLenProbe;
        const paddingAmount = computePaddingExtensionBody(probeMessageSize, config);
        if (paddingAmount > 0) {
            finalExtensions = buildClientHelloExtensions(config, keyPairs, sentinels, provider, cookie, paddingAmount);
        }
    }

    const bodyLen =
        2 + randomBytes.length + 1 + sessionId.length +
        2 + cipherSuitesBytes.length +
        1 + compressionMethods.length +
        2 + finalExtensions.length;

    const message = new Uint8Array(1 + 3 + bodyLen);
    let o = 0;
    message[o++] = HandshakeType.CLIENT_HELLO;
    message[o++] = (bodyLen >> 16) & 0xff;
    message[o++] = (bodyLen >> 8) & 0xff;
    message[o++] = bodyLen & 0xff;
    message[o++] = (TLS_1_2_WIRE_VERSION >> 8) & 0xff;
    message[o++] = TLS_1_2_WIRE_VERSION & 0xff;
    message.set(randomBytes, o);
    o += randomBytes.length;
    message[o++] = sessionId.length & 0xff;
    message.set(sessionId, o);
    o += sessionId.length;
    message[o++] = (cipherSuitesBytes.length >> 8) & 0xff;
    message[o++] = cipherSuitesBytes.length & 0xff;
    message.set(cipherSuitesBytes, o);
    o += cipherSuitesBytes.length;
    message[o++] = compressionMethods.length & 0xff;
    message.set(compressionMethods, o);
    o += compressionMethods.length;
    message[o++] = (finalExtensions.length >> 8) & 0xff;
    message[o++] = finalExtensions.length & 0xff;
    message.set(finalExtensions, o);

    return message;
}

function buildClientHelloExtensions(
    config: ClientHelloConfig,
    keyPairs: readonly KeyPair[],
    sentinels: GreaseSentinels | undefined,
    provider: CryptoProvider,
    cookie?: Uint8Array,
    paddingAmount = 0,
): Uint8Array {
    const order = sentinels === undefined
        ? [...config.extensionOrder]
        : [sentinels.leadingExtension, ...config.extensionOrder];

    const parts: Uint8Array[] = [];
    let paddingInOrder = false;
    for (const type of order) {
        if (type === ExtensionType.PADDING) {
            paddingInOrder = true;
        }
        const body = encodeExtensionBody(type, config, keyPairs, sentinels, provider, paddingAmount);
        // Unknown extension types return undefined (no encoder). Skip them so
        // they don't bloat the ClientHello. GREASE, padding, SCT, EMS, etc. all
        // legitimately produce zero-length bodies — they must still be emitted.
        if (body === undefined) { continue; }
        parts.push(wrapExtension(type, body));
    }

    // RFC 8446 §4.2.2: when the server sent a cookie in HelloRetryRequest, the
    // client MUST echo it in the new ClientHello. The cookie extension is
    // appended after the profile's extensions so the original fingerprint order
    // is preserved.
    if (cookie !== undefined && cookie.length > 0) {
        parts.push(wrapExtension(ExtensionType.COOKIE, encodeCookie(cookie)));
    }

    // When padding is needed and the PADDING extension was not in the profile's
    // extension order, append it at the very end (real browsers place it last).
    if (!paddingInOrder && paddingAmount > 0) {
        parts.push(wrapExtension(ExtensionType.PADDING, new Uint8Array(paddingAmount)));
    }

    // RFC 8701: Chrome appends a trailing GREASE extension as the absolute last
    // extension on the wire (after padding), with an INDEPENDENTLY drawn
    // 0x?a?a type (never equal to the leading GREASE extension — RFC 8446 §4.2
    // forbids duplicate extension types). Its body is a single 0x00 byte:
    // golden chrome-131 terminates with `5a5a 0001 00`.
    if (sentinels !== undefined) {
        parts.push(wrapExtension(sentinels.trailingExtension, new Uint8Array(1)));
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

function encodeExtensionBody(
    type: number,
    config: ClientHelloConfig,
    keyPairs: readonly KeyPair[],
    sentinels: GreaseSentinels | undefined,
    provider: CryptoProvider,
    paddingAmount = 0,
): Uint8Array | undefined {
    switch (type) {
        case ExtensionType.SERVER_NAME:
            return encodeServerNameList(config.serverName);
        case ExtensionType.STATUS_REQUEST:
            return encodeStatusRequest();
        case ExtensionType.SUPPORTED_GROUPS:
            return encodeSupportedGroups(config.supportedGroups ?? config.keyShareGroups, sentinels?.supportedGroups);
        case ExtensionType.EC_POINT_FORMATS:
            return encodeEcPointFormats(config.ecPointFormats);
        case ExtensionType.SIGNATURE_ALGORITHMS:
            return encodeSignatureAlgorithms(config.signatureAlgorithms);
        case ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            return config.alpnProtocols !== undefined && config.alpnProtocols.length > 0
                ? encodeAlpn(config.alpnProtocols)
                : new Uint8Array(0);
        case ExtensionType.APPLICATION_SETTINGS:
            return encodeApplicationSettings(config.alpnProtocols);
        case ExtensionType.APPLICATION_SETTINGS_OLD:
            return encodeApplicationSettings(config.alpnProtocols);
        case ExtensionType.ENCRYPTED_CLIENT_HELLO:
            return encodeEchGrease(provider);
        case ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP:
            return new Uint8Array(0);
        case ExtensionType.EXTENDED_MASTER_SECRET:
            return new Uint8Array(0);
        case ExtensionType.COMPRESS_CERTIFICATE:
            return encodeCompressCertificate();
        case ExtensionType.SESSION_TICKET:
            return new Uint8Array(0);
        case ExtensionType.PRE_SHARED_KEY:
            // No PSK identities to offer — skip the extension entirely.
            // RFC 8446 §4.2.11 requires PSK to have ≥7 bytes and be the LAST
            // extension. Sending an empty body mid-order causes server rejection.
            return undefined;
        case ExtensionType.SUPPORTED_VERSIONS:
            return encodeSupportedVersionsClient(
                config.supportedVersions,
                sentinels?.supportedVersions,
            );
        case ExtensionType.PSK_KEY_EXCHANGE_MODES:
            return encodePskKeyExchangeModes();
        case ExtensionType.KEY_SHARE:
            return encodeKeyShareClient(keyPairs, sentinels?.keyShareGroup);
        case ExtensionType.PADDING:
            // RFC 7685: the body is a run of zero bytes. The length is computed
            // by the caller via computePaddingExtensionBody and threaded through.
            return new Uint8Array(paddingAmount);
        case ExtensionType.RENEGOTIATION_INFO:
            return encodeRenegotiationInfo();
        default:
            if (isGreaseValue(type)) {
                return new Uint8Array(0);
            }
            // Unknown extension type (e.g. extended_random 0x1c, or 0x22 in the
            // firefox-128 profile): return undefined so the caller skips it.
            return undefined;
    }
}

function encodeSupportedGroups(groups: readonly NamedGroup[], greaseValue?: number): Uint8Array {
    // Emit ALL offered groups verbatim — including post-quantum hybrids like
    // X25519MLKEM768 (0x11ec). They must appear in supported_groups for the
    // JA3/JA4 fingerprint to match real browsers. The crypto backend falls back
    // to the classical X25519 half if a server actually selects a hybrid.
    // Chrome prepends a GREASE group when grease is enabled.
    const totalGroups = greaseValue === undefined ? groups.length : groups.length + 1;
    const out = new Uint8Array(2 + totalGroups * 2);
    out[0] = ((totalGroups * 2) >> 8) & 0xff;
    out[1] = (totalGroups * 2) & 0xff;
    let offset = 2;
    if (greaseValue !== undefined) {
        out[0 + offset - 2] = ((totalGroups * 2) >> 8) & 0xff; // already set above
        out[offset] = (greaseValue >> 8) & 0xff;
        out[offset + 1] = greaseValue & 0xff;
        offset += 2;
    }
    for (let i = 0; i < groups.length; i++) {
        const group = groups[i];
        if (group === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`supported group at index ${i} is missing`),
            });
        }
        const wire = namedGroupToWire(group);
        out[offset + i * 2] = (wire >> 8) & 0xff;
        out[offset + i * 2 + 1] = wire & 0xff;
    }
    return out;
}

/** Default EC point formats: uncompressed (0x00) only. */
const DEFAULT_EC_POINT_FORMATS: readonly number[] = [0x00];

/**
 * Encode the `ec_point_formats` extension body from config.
 *
 * Defaults to `[0x00]` (uncompressed) when the profile omits the field. Real
 * browsers list `[0x01, 0x00]` (ansiX962_compressed_prime + uncompressed) — the
 * exact ordering is a fingerprint signal, so it flows from the profile.
 */
function encodeEcPointFormats(formats: readonly number[] | undefined): Uint8Array {
    const list = formats ?? DEFAULT_EC_POINT_FORMATS;
    const out = new Uint8Array(1 + list.length);
    out[0] = list.length & 0xff;
    for (let i = 0; i < list.length; i++) {
        const fmt = list[i];
        /* v8 ignore next 3 */
        if (fmt === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`EC point format at index ${i} is missing`),
            });
        }
        out[1 + i] = fmt & 0xff;
    }
    return out;
}

/**
 * Encode the ALPS (application_settings) extension body.
 *
 * ALPS is h2-specific by design (the settings travel in HTTP/2 SETTINGS), so
 * real Chrome advertises ONLY "h2" here even though the ALPN extension carries
 * the full h2+http/1.1 list — golden chrome-131 sends `00 03 02 'h2'` (5B).
 * When the offered ALPN list contains no h2, the extension is omitted
 * entirely (returning undefined makes the caller skip it).
 */
function encodeApplicationSettings(alpnProtocols: readonly string[] | undefined): Uint8Array | undefined {
    const offered = alpnProtocols !== undefined && alpnProtocols.length > 0 ? alpnProtocols : ["h2"];
    if (!offered.includes("h2")) {
        return undefined;
    }
    return encodeAlpn(["h2"]);
}

/** Default compress_certificate algorithms: brotli (0x02) only. */
// DEFAULT_COMPRESS_ALGORITHMS removed — compress_certificate is now skipped.

/**
 * Encode the `compress_certificate` extension body (RFC 8879) from config.
 *
 * Defaults to `[0x02]` (brotli) when the profile omits the field. Real Chrome
 * lists `[0x02, 0x01, 0x03]` (brotli, zlib, zstd) — the exact ordering and set
 * are fingerprint signals, so they flow from the profile.
 */
// encodeCompressCertificate removed — we skip the compress_certificate extension
// because we have no certificate decompression implementation. See the
// COMPRESS_CERTIFICATE case in encodeExtensionBody above.

function encodePskKeyExchangeModes(): Uint8Array {
    return new Uint8Array([0x01, 0x01]);
}

function encodeStatusRequest(): Uint8Array {
    return new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00]);
}

/**
 * ECH GREASE — byte-shape replicated from real Chrome 131 and Firefox 133
 * wire captures (browsercore-testing captures, tls/client_hello.bin per profile):
 *
 *   00 00 01 00 01 <1 random> | 00 20 <32 random enc> | <2B len> <random payload>
 *
 * Both browsers emit exactly this shape (218 bytes total for Chrome, 186 for
 * Firefox — only the payload length differs). The middle fields are opaque to
 * any observer: a real client HPKE-seals a dummy inner ClientHello with an
 * ephemeral key, so the enc/payload bytes are ciphertext that never repeats.
 * Matching the observed shape is what strict ECH-aware edges
 * (Cloudflare/BoringSSL) accept; a spec-shaped body with an empty enc gets
 * the ClientHello rejected with decode_error. JA3/JA4 hash only the extension
 * type code, so the goal here is server acceptance with fresh randomness.
 */
function encodeEchGrease(provider: CryptoProvider): Uint8Array {
    const enc = provider.randomBytes(32);
    const payload = provider.randomBytes(176);
    const body = new Uint8Array(6 + 2 + enc.length + 2 + payload.length);
    body.set([0x00, 0x00, 0x01, 0x00, 0x01], 0);
    const jitter = provider.randomBytes(1)[0];
    /* v8 ignore next -- randomBytes(1) always yields a byte */
    body[5] = jitter ?? 0x00;
    body[6] = 0x00; // enc length: 32
    body[7] = 0x20;
    body.set(enc, 8);
    const o = 8 + enc.length;
    body[o] = (payload.length >> 8) & 0xff;
    body[o + 1] = payload.length & 0xff;
    body.set(payload, o + 2);
    return body;
}

/**
 * compress_certificate (RFC 8879) — advertise exactly what real Chrome
 * advertises: one algorithm, brotli (0x0002). Byte-identical to the golden
 * chrome-131 capture (`02 00 02`). Honored at the Certificate stage via the
 * injected CompressionProvider (see CompressedCertificate handling); the
 * caller strips ext 27 when no provider is injected.
 */
function encodeCompressCertificate(): Uint8Array {
    return new Uint8Array([0x02, 0x00, 0x02]);
}

function encodeRenegotiationInfo(): Uint8Array {
    return new Uint8Array([0x00]);
}

/**
 * Encode a cookie extension body (RFC 8446 §4.2.2).
 *
 * Layout: `cookie_length(2) || cookie`. The cookie is an opaque blob the server
 * sent in HelloRetryRequest; the client echoes it verbatim.
 */
function encodeCookie(cookie: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + cookie.length);
    out[0] = (cookie.length >> 8) & 0xff;
    out[1] = cookie.length & 0xff;
    out.set(cookie, 2);
    return out;
}

function wrapExtension(type: number, data: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + 2 + data.length);
    out[0] = (type >> 8) & 0xff;
    out[1] = type & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out[3] = data.length & 0xff;
    out.set(data, 4);
    return out;
}

function encodeServerNameList(serverName: string): Uint8Array {
    const nameBytes = new TextEncoder().encode(serverName);
    if (nameBytes.length > 0xffff) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("SNI server_name exceeds 65535 bytes"),
        });
    }
    const entry = new Uint8Array(1 + 2 + nameBytes.length);
    entry[0] = 0;
    entry[1] = (nameBytes.length >> 8) & 0xff;
    entry[2] = nameBytes.length & 0xff;
    entry.set(nameBytes, 3);
    const out = new Uint8Array(2 + entry.length);
    out[0] = (entry.length >> 8) & 0xff;
    out[1] = entry.length & 0xff;
    out.set(entry, 2);
    return out;
}

function encodeSupportedVersionsClient(versions: readonly ProtocolVersion[], greaseValue?: number): Uint8Array {
    // Chrome advertises [GREASE, TLS 1.3, TLS 1.2] in supported_versions. The
    // leading GREASE version (0x?a?a) is drawn independently for this slot
    // (golden chrome-131: supported_versions 0x4a4a while the cipher list
    // carries 0x5a5a). TLS 1.2 (0x0303) is appended for
    // middlebox compatibility even though the handshake only negotiates TLS 1.3:
    // omitting it is a fingerprint signal that distinguishes this client from
    // real Chrome, and some middleboxes force a downgrade when 1.2 is absent.
    const allVersions: number[] = [];
    if (greaseValue !== undefined) {
        allVersions.push(greaseValue);
    }
    for (let i = 0; i < versions.length; i++) {
        const version = versions[i];
        if (version === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`supported version at index ${i} is missing`),
            });
        }
        allVersions.push(version.wire);
    }
    if (!allVersions.includes(TLS_1_2_WIRE_VERSION)) {
        allVersions.push(TLS_1_2_WIRE_VERSION);
    }
    const out = new Uint8Array(1 + allVersions.length * 2);
    out[0] = (allVersions.length * 2) & 0xff;
    for (let i = 0; i < allVersions.length; i++) {
        const wire = allVersions[i];
        /* v8 ignore next 3 */
        if (wire === undefined) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`supported version wire at index ${i} is missing`),
            });
        }
        out[1 + i * 2] = (wire >> 8) & 0xff;
        out[1 + i * 2 + 1] = wire & 0xff;
    }
    return out;
}

function encodeKeyShareClient(
    keyPairs: readonly KeyPair[],
    greaseGroup: number | undefined,
): Uint8Array {
    // Emit ALL offered key pairs — including post-quantum hybrid groups like
    // X25519MLKEM768 (0x11ec). They must appear in the key_share extension for
    // the JA3/JA4 fingerprint to match real browsers. The crypto backend
    // generates an X25519 key tagged with the hybrid name; the server will
    // typically select the classical X25519 group for the actual exchange.
    const greaseEntry = greaseGroup === undefined ? 0 : 2 + 2 + GREASE_KEY_LENGTH;
    let entriesLen = greaseEntry;
    for (const kp of keyPairs) {
        entriesLen += 2 + 2 + kp.publicKey.length;
    }
    const out = new Uint8Array(2 + entriesLen);
    out[0] = (entriesLen >> 8) & 0xff;
    out[1] = entriesLen & 0xff;
    let o = 2;
    if (greaseGroup !== undefined) {
        out[o++] = (greaseGroup >> 8) & 0xff;
        out[o++] = greaseGroup & 0xff;
        out[o++] = (GREASE_KEY_LENGTH >> 8) & 0xff;
        out[o++] = GREASE_KEY_LENGTH & 0xff;
        // Real Chrome sends a literal 0x00 byte here (golden chrome-131:
        // `caca 0001 00`), not random bytes.
        out.set(GREASE_KEY_PAYLOAD, o);
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
