/**
 * TLS 1.3 session resumption cache (RFC 8446 §4.6.1, §7.5).
 *
 * When the server sends a NewSessionTicket post-handshake, the client derives a
 * resumption PSK from the resumption_master_secret and stores it alongside the
 * ticket for future 0-RTT / PSK-based session resumption. This module owns the
 * storage and the ticket parsing/PSK derivation; the PSK offer in a subsequent
 * ClientHello is a separate concern.
 *
 * The cache is a simple `Map` keyed by the SNI server name — sufficient for the
 * single-connection resumption scope this package supports. A production-grade
 * implementation would add TTL expiry and LRU eviction, but those are policy
 * decisions that belong in the caller, not here.
 */

import type { CryptoProvider, HashId } from "@browsercore/crypto";
import type { CipherSuite } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { hkdfExpandLabel, hashLengthFor } from "../crypto/keySchedule.js";
import { transcriptHash } from "../connection/key-exchange.js";

/** A parsed NewSessionTicket plus the derived resumption PSK. */
export interface ResumptionTicket {
    /** The opaque ticket identity the server issued (to echo in a future ClientHello). */
    readonly ticket: Uint8Array;
    /** Obfuscated age addend from the ticket (RFC 8446 §4.6.1). */
    readonly ticketAgeAdd: number;
    /** Maximum early-data size in bytes, or 0 if the ticket disallows 0-RTT. */
    readonly maxEarlyDataSize: number;
    /** Derived resumption PSK (HKDF-Expand-Label of the resumption_master_secret). */
    readonly psk: Uint8Array;
    /** Cipher suite under which the original handshake negotiated the ticket. */
    readonly cipherSuite: CipherSuite;
    /** Epoch milliseconds when the ticket was received (for TTL enforcement). */
    readonly receivedAt: number;
}

/**
 * A simple session resumption cache.
 *
 * Keyed by the server name (SNI) — one outstanding ticket per host. Thread-safe
 * by virtue of JavaScript's single-threaded model; concurrent connections to the
 * same host simply overwrite the stored ticket (the most recent one wins).
 */
export class SessionCache {
    private readonly entries = new Map<string, ResumptionTicket>();

    /** Store a resumption ticket for the given server name. */
    store(serverName: string, ticket: ResumptionTicket): void {
        this.entries.set(serverName, ticket);
    }

    /** Retrieve the most recent ticket for a server name, or undefined. */
    get(serverName: string): ResumptionTicket | undefined {
        return this.entries.get(serverName);
    }

    /** Return true if a ticket exists for the given server name. */
    has(serverName: string): boolean {
        return this.entries.has(serverName);
    }

    /** Remove the stored ticket for a server name (no-op if absent). */
    delete(serverName: string): void {
        this.entries.delete(serverName);
    }

    /** Remove all stored tickets. */
    clear(): void {
        this.entries.clear();
    }

    /** Number of cached tickets. */
    get size(): number {
        return this.entries.size;
    }
}

/**
 * Result of parsing a NewSessionTicket: the key under which to store it plus
 * the typed ticket. Returned by {@link parseNewSessionTicket} so the caller can
 * decide whether to store it.
 */
export interface ParsedNewSessionTicket {
    readonly serverName: string;
    readonly ticket: ResumptionTicket;
}

/** early_data extension type (RFC 8446 §4.2.10), used in NewSessionTicket. */
const EARLY_DATA_EXTENSION_TYPE = 42;

/**
 * Parse a NewSessionTicket (RFC 8446 §4.6.1) body and derive the resumption PSK.
 *
 * The resumption_master_secret is derived from the master secret and the full
 * transcript (ClientHello..client Finished). The PSK is
 * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
 * Hash.length).
 *
 * @param body          The NewSessionTicket message body (after the 4-byte
 *                       handshake header).
 * @param masterSecret  The master secret from the handshake key schedule.
 * @param transcript    The full handshake transcript (must include the client
 *                       Finished message per RFC 8446 §7.5).
 * @param hash          The negotiated cipher's hash (SHA-256 or SHA-384).
 * @param cipherSuite   The negotiated cipher suite.
 * @param serverName    The SNI server name (cache key).
 * @param receivedAt    Epoch milliseconds when the ticket was received.
 * @param provider      The injected crypto provider.
 * @returns The parsed ticket + cache key, or undefined if the body is malformed.
 */
export function parseNewSessionTicket(
    body: Uint8Array,
    masterSecret: Uint8Array,
    transcript: readonly Uint8Array[],
    hash: HashId,
    cipherSuite: CipherSuite,
    serverName: string,
    receivedAt: number,
    provider: CryptoProvider,
): ParsedNewSessionTicket | undefined {
    if (body.length < 8) {
        return undefined;
    }

    // ticket_lifetime(4) — not needed for PSK derivation; skip 4 bytes.
    // ticket_age_add(4)
    const ticketAgeAdd = readUint32(body, 4);

    let o = 8;

    // ticket_nonce<0..255>: 1-byte length + nonce bytes
    const nonceResult = readOpaque8(body, o);
    if (nonceResult === undefined) {
        return undefined;
    }
    const ticketNonce = nonceResult.data;
    o = nonceResult.nextOffset;

    // ticket<1..2^16-1>: 2-byte length + ticket bytes
    const ticketResult = readOpaque16(body, o);
    if (ticketResult === undefined) {
        return undefined;
    }
    const ticket = ticketResult.data;
    o = ticketResult.nextOffset;

    // extensions<8..2^16-2>: scan for early_data (type 42) to get max_early_data_size.
    let maxEarlyDataSize = 0;
    const extHeader = readUint16(body, o);
    if (extHeader !== undefined) {
        const extLen = extHeader.value;
        o = extHeader.nextOffset;
        const extEnd = Math.min(o + extLen, body.length);
        let scanning = true;
        while (scanning && o + 4 <= extEnd) {
            const eType = readUint16(body, o);
            const eLen = readUint16(body, o + 2);
            if (eType === undefined || eLen === undefined) {
                scanning = false;
                break;
            }
            o += 4;
            if (o + eLen.value > extEnd) {
                break;
            }
            if (eType.value === EARLY_DATA_EXTENSION_TYPE && eLen.value >= 4) {
                maxEarlyDataSize = readUint32(body, o);
            }
            o += eLen.value;
        }
    }

    // Derive resumption_master_secret (RFC 8446 §7.5).
    const resumptionTranscript = transcriptHash(transcript, hash, provider);
    const hashLen = hashLengthFor(hash);
    const resumptionMasterSecret = hkdfExpandLabel(
        masterSecret, "res master", resumptionTranscript, hashLen, hash, provider,
    );

    // Derive PSK (RFC 8446 §7.5).
    const psk = hkdfExpandLabel(
        resumptionMasterSecret, "resumption", ticketNonce, hashLen, hash, provider,
    );

    return {
        serverName,
        ticket: {
            ticket: new Uint8Array(ticket),
            ticketAgeAdd,
            maxEarlyDataSize,
            psk,
            cipherSuite,
            receivedAt,
        },
    };
}

/** Read a big-endian uint32 at the given offset. Caller guarantees bounds. */
function readUint32(buf: Uint8Array, offset: number): number {
    const b0 = buf[offset];
    const b1 = buf[offset + 1];
    const b2 = buf[offset + 2];
    const b3 = buf[offset + 3];
    if (b0 === undefined || b1 === undefined || b2 === undefined || b3 === undefined) {
        throw new TlsHandshakeError("application", {
            cause: new Error("readUint32: buffer truncated"),
        });
    }
    // `>>> 0` converts the signed 32-bit bitwise result to unsigned uint32.
    return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

/** Read a big-endian uint16 at the given offset; returns undefined if truncated. */
function readUint16(buf: Uint8Array, offset: number): { value: number; nextOffset: number } | undefined {
    const hi = buf[offset];
    const lo = buf[offset + 1];
    if (hi === undefined || lo === undefined) {
        return undefined;
    }
    return { value: (hi << 8) | lo, nextOffset: offset + 2 };
}

/** Read a 1-byte-length-prefixed opaque blob; returns the data and next offset. */
function readOpaque8(buf: Uint8Array, offset: number): { data: Uint8Array; nextOffset: number } | undefined {
    const lenByte = buf[offset];
    if (lenByte === undefined) {
        return undefined;
    }
    const len = lenByte;
    const start = offset + 1;
    if (start + len > buf.length) {
        return undefined;
    }
    return { data: buf.subarray(start, start + len), nextOffset: start + len };
}

/** Read a 2-byte-length-prefixed opaque blob; returns the data and next offset. */
function readOpaque16(buf: Uint8Array, offset: number): { data: Uint8Array; nextOffset: number } | undefined {
    const hi = buf[offset];
    const lo = buf[offset + 1];
    if (hi === undefined || lo === undefined) {
        return undefined;
    }
    const len = (hi << 8) | lo;
    const start = offset + 2;
    if (start + len > buf.length) {
        return undefined;
    }
    return { data: buf.subarray(start, start + len), nextOffset: start + len };
}
