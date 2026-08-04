/**
 * RFC 8701 GREASE (Generate Random Extensions And Sustain Extensibility).
 *
 * Implements the reserved sentinel values that TLS clients advertise to ensure
 * peers correctly handle unknown values. A buggy server that rejects unknowns
 * fails visibly instead of rusting shut undetected.
 *
 * GREASE must appear in: cipher suites (first position for Chrome/Edge/Safari),
 * extension types, supported_versions, key_share groups, and supported_groups.
 * Firefox does not grease (profile.grease = false).
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc8701
 * Verified against: curl-impersonate (lwthiker/curl-impersonate) which enables
 * GREASE via `SSL_CTX_set_grease_enabled(ctx, 1)` for Chrome impersonation.
 */

import type { ClientHello } from "./handshake-types.js";
import { ExtensionType } from "../extensions/extensions.js";

/**
 * The 16 GREASE sentinel values reserved by RFC 8701 §2.
 *
 * Each value has identical bytes (high === low) with low nibble 0xA, giving
 * the pattern 0x?A?A. Reserved across cipher suites, ALPN identifiers,
 * extension types, named groups, signature algorithms, and versions.
 */
export const GREASE_VALUES: readonly number[] = Object.freeze([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/**
 * Minimal profile shape for GREASE decisions.
 *
 * The grease module depends only on this boolean — not the full TlsProfile —
 * so it applies independently of profile resolution. Chrome/Edge/Safari set
 * `grease: true`; Firefox sets `grease: false`.
 */
export interface Profile {
    readonly grease: boolean;
}

/** Pick a random element from a non-empty read-only array. */
function pickRandom<T>(values: readonly T[], random: () => number): T {
    const index = Math.floor(random() * values.length);
    const value = values[index];
    if (value === undefined) {
        // Length > 0 is guaranteed by every caller; this is an invariant guard.
        throw new Error("pickRandom: unreachable — values array is empty");
    }
    return value;
}

/**
 * Pick a GREASE value not already present in `exclude`.
 *
 * RFC 8701 §5 forbids duplicate extension types within a block; the same
 * rule is applied uniformly so a GREASE value never collides with an
 * existing entry. Throws if every sentinel is excluded — a degenerate case
 * that signals a programming error in the caller.
 */
function pickUniqueGrease(exclude: readonly number[], random: () => number): number {
    const available = GREASE_VALUES.filter((v) => !exclude.includes(v));
    return pickRandom(available, random);
}

/**
 * Generate a random GREASE cipher suite value.
 *
 * Returns one of the 16 RFC 8701 sentinels. The random source is injectable
 * for deterministic testing; defaults to Math.random for production use.
 */
export function generateGreaseCipherSuite(random: () => number = Math.random): number {
    return pickRandom(GREASE_VALUES, random);
}

/**
 * Generate a random GREASE extension type value.
 *
 * The extension-type sentinels share the same numeric space as the cipher
 * suite sentinels (RFC 8701 §2), so this draws from the same set.
 */
export function generateGreaseExtensionType(random: () => number = Math.random): number {
    return pickRandom(GREASE_VALUES, random);
}

/**
 * Insert a GREASE value at the head of a list.
 *
 * Chrome/Edge/Safari place the GREASE cipher suite first in cipher_suites so
 * that servers conditioning on position 0 still see a GREASE value. The
 * returned GREASE value never duplicates an existing entry (RFC 8701 §5).
 */
export function insertGrease(values: readonly number[], random: () => number = Math.random): number[] {
    const grease = pickUniqueGrease(values, random);
    return [grease, ...values];
}

/** A parsed extension: type + opaque data. */
interface RawExtension {
    readonly type: number;
    readonly data: Uint8Array;
}

/**
 * Parse a ClientHello extensions block (length-prefixed list) into raw entries.
 *
 * Tolerant of unknown types — returns the raw uint16 instead of throwing — so
 * it can round-trip GREASE extensions that are not in the ExtensionType enum.
 *
 * Reads bytes one at a time (mirroring extensions.ts) so truncation mid-block
 * is caught by the per-byte bounds check instead of reading past the buffer.
 * A declared length that exceeds the actual buffer triggers the readByte throw.
 */
function parseExtensionsRaw(buf: Uint8Array): RawExtension[] {
    if (buf.length < 2) {
        return [];
    }
    let offset = 0;
    const readByte = (): number => {
        const byte = buf[offset];
        if (byte === undefined) {
            // Declared length exceeds actual buffer — surface as a parse error
            // rather than silently producing corrupt output.
            throw new Error(`extension byte truncated at offset ${offset}`);
        }
        offset++;
        return byte;
    };
    const totalLen = (readByte() << 8) | readByte();
    const result: RawExtension[] = [];
    // NOTE: intentionally NOT capped at buf.length — a too-large totalLen makes
    // the loop attempt to read past the buffer, triggering the readByte throw.
    const end = 2 + totalLen;
    while (offset < end) {
        if (offset + 4 > end) {
            // Not enough bytes for a full extension header — stop.
            break;
        }
        const type = (readByte() << 8) | readByte();
        const dataLen = (readByte() << 8) | readByte();
        const dataStart = offset;
        const dataEnd = dataStart + dataLen;
        if (dataEnd > end) {
            // Declared data length exceeds the block — stop before over-read.
            break;
        }
        result.push({ type, data: buf.subarray(dataStart, dataEnd) });
        offset = dataEnd;
    }
    return result;
}

/** Serialize raw extensions back into a length-prefixed ClientHello block. */
function serializeExtensionsRaw(extensions: readonly RawExtension[]): Uint8Array {
    let total = 0;
    for (const ext of extensions) {
        total += 4 + ext.data.length;
    }
    const out = new Uint8Array(2 + total);
    out[0] = (total >> 8) & 0xff;
    out[1] = total & 0xff;
    let offset = 2;
    for (const ext of extensions) {
        out[offset++] = (ext.type >> 8) & 0xff;
        out[offset++] = ext.type & 0xff;
        out[offset++] = (ext.data.length >> 8) & 0xff;
        out[offset++] = ext.data.length & 0xff;
        out.set(ext.data, offset);
        offset += ext.data.length;
    }
    return out;
}

/**
 * Read a uint16 from `data` at byte `offset`, or 0 if too short.
 *
 * The defensive fallback (returning 0) is exercised only when the caller
 * passes a truncated body — handled explicitly in tests.
 */
function readUint16(data: Uint8Array, offset: number): number {
    const hi = data[offset];
    const lo = data[offset + 1];
    if (hi === undefined || lo === undefined) {
        return 0;
    }
    return (hi << 8) | lo;
}

/**
 * Prepend a 2-byte value to a 1-byte-length-prefixed list (supported_versions).
 *
 * Layout: length(1) || values*(2). The length byte counts only the bytes that
 * follow it. Uses the same read-twice-then-check pattern as key-exchange.ts /
 * server-hello.ts so the indexed access satisfies noUncheckedIndexedAccess and
 * the defensive branch stays reachable (empty body → fallback to 0).
 */
function prependToVersionList(data: Uint8Array, value: number): Uint8Array {
    const lenByte = data[0];
    const listLen = lenByte ?? 0;
    const out = new Uint8Array(1 + listLen + 2);
    out[0] = (listLen + 2) & 0xff;
    out[1] = (value >> 8) & 0xff;
    out[2] = value & 0xff;
    out.set(data.subarray(1), 3);
    return out;
}

/**
 * Prepend a 2-byte value to a 2-byte-length-prefixed list (supported_groups).
 *
 * Layout: length(2) || values*(2). The length field counts only the bytes that
 * follow it.
 */
function prependToGroupList(data: Uint8Array, value: number): Uint8Array {
    const listLen = readUint16(data, 0);
    const out = new Uint8Array(2 + listLen + 2);
    out[0] = ((listLen + 2) >> 8) & 0xff;
    out[1] = (listLen + 2) & 0xff;
    out[2] = (value >> 8) & 0xff;
    out[3] = value & 0xff;
    out.set(data.subarray(2), 4);
    return out;
}

/**
 * Prepend a key share entry to a 2-byte-length-prefixed key_share list.
 *
 * Layout: length(2) || entries*(group(2) + key_len(2) + key_exchange). The
 * GREASE entry carries an empty key_exchange (length 0) — RFC 8701 §3.1 says
 * the key_exchange field MAY be any value for GREASE entries.
 */
function prependKeyShare(data: Uint8Array, group: number): Uint8Array {
    const listLen = readUint16(data, 0);
    const keyLen = 0;
    const entryLen = 2 + 2 + keyLen;
    const out = new Uint8Array(2 + entryLen + listLen);
    out[0] = ((listLen + entryLen) >> 8) & 0xff;
    out[1] = (listLen + entryLen) & 0xff;
    // GREASE entry at the body head.
    out[2] = (group >> 8) & 0xff;
    out[3] = group & 0xff;
    out[4] = (keyLen >> 8) & 0xff;
    out[5] = keyLen & 0xff;
    // Existing entries follow.
    out.set(data.subarray(2), 2 + entryLen);
    return out;
}

/**
 * Apply GREASE to a ClientHello extensions block.
 *
 * Mutates the block in three ways:
 *  - supported_versions (if present): prepend a GREASE version sentinel.
 *  - supported_groups (if present): prepend a GREASE group sentinel.
 *  - key_share (if present): prepend a GREASE key share entry.
 *  - append 1–2 GREASE extension types with empty data.
 */
function applyGreaseToExtensions(buf: Uint8Array, random: () => number): Uint8Array {
    const extensions = parseExtensionsRaw(buf);
    const greased: RawExtension[] = [];
    const used: number[] = [];

    for (const ext of extensions) {
        switch (ext.type) {
            case ExtensionType.SUPPORTED_VERSIONS: {
                const g = pickUniqueGrease(used, random);
                used.push(g);
                greased.push({ type: ext.type, data: prependToVersionList(ext.data, g) });
                break;
            }
            case ExtensionType.SUPPORTED_GROUPS: {
                const g = pickUniqueGrease(used, random);
                used.push(g);
                greased.push({ type: ext.type, data: prependToGroupList(ext.data, g) });
                break;
            }
            case ExtensionType.KEY_SHARE: {
                const g = pickUniqueGrease(used, random);
                used.push(g);
                greased.push({ type: ext.type, data: prependKeyShare(ext.data, g) });
                break;
            }
            default:
                // Unknown / non-GREASE-sensitive extension — pass through.
                greased.push(ext);
                break;
        }
    }

    // Append 1–2 GREASE extension types. Chrome alternates between one and two.
    const extraCount = 1 + Math.floor(random() * 2);
    for (let i = 0; i < extraCount; i++) {
        const g = pickUniqueGrease(used, random);
        used.push(g);
        greased.push({ type: g, data: new Uint8Array(0) });
    }

    return serializeExtensionsRaw(greased);
}

/**
 * Apply all GREASE transformations to a ClientHello.
 *
 * When `profile.grease` is false (Firefox), returns the input unchanged.
 * When true (Chrome/Edge/Safari), returns a new ClientHello with:
 *  - a GREASE cipher suite prepended to cipherSuites,
 *  - GREASE values injected into supported_versions / supported_groups /
 *    key_share extensions (when present),
 *  - 1–2 GREASE extension types appended to the extensions block.
 *
 * The original ClientHello is never mutated (immutable data rule).
 */
export function applyGreaseToClientHello(
    hello: ClientHello,
    profile: Profile,
    random: () => number = Math.random,
): ClientHello {
    if (!profile.grease) {
        return hello;
    }

    return {
        protocolVersion: hello.protocolVersion,
        random: hello.random,
        sessionId: hello.sessionId,
        cipherSuites: insertGrease(hello.cipherSuites, random),
        compressionMethods: hello.compressionMethods,
        extensions: applyGreaseToExtensions(hello.extensions, random),
    };
}
