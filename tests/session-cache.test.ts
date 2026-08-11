/**
 * Tests for the session resumption cache and NewSessionTicket parsing
 * (RFC 8446 §4.6.1, §7.5).
 *
 * Covers the {@link SessionCache} Map-based storage (store/get/has/delete/clear/
 * size) and {@link parseNewSessionTicket} — which parses the wire format,
 * derives the resumption_master_secret + PSK, and extracts max_early_data_size
 * from the early_data extension.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import {
    SessionCache,
    parseNewSessionTicket,
    type ResumptionTicket,
} from "../src/session/session-cache.js";
import { TLS_1_3 } from "../src/types.js";
import type { CipherSuite } from "../src/types.js";

const CIPHER_SUITE: CipherSuite = "TLS_AES_128_GCM_SHA256";

/**
 * Build a well-formed NewSessionTicket body for testing.
 *
 * Layout: ticket_lifetime(4) || ticket_age_add(4) || ticket_nonce<0..255>
 * || ticket<1..2^16-1> || extensions<8..2^16-2>.
 */
function buildTicketBody(opts: {
    readonly ticketLifetime?: number;
    readonly ticketAgeAdd?: number;
    readonly ticketNonce?: Uint8Array;
    readonly ticket?: Uint8Array;
    readonly earlyDataMax?: number;
} = {}): Uint8Array {
    const lifetime = opts.ticketLifetime ?? 7200;
    const ageAdd = opts.ticketAgeAdd ?? 0x12345678;
    const nonce = opts.ticketNonce ?? new Uint8Array([0x01]);
    const ticket = opts.ticket ?? new Uint8Array(32).fill(0xab);
    const hashLen = 32; // SHA-256

    // early_data extension (type 42) with a 4-byte max_early_data_size.
    let extensions = new Uint8Array(0);
    if (opts.earlyDataMax !== undefined) {
        const ed = new Uint8Array(8);
        ed[0] = 0; ed[1] = 42; // type
        ed[2] = 0; ed[3] = 4;  // length
        ed[4] = (opts.earlyDataMax >> 24) & 0xff;
        ed[5] = (opts.earlyDataMax >> 16) & 0xff;
        ed[6] = (opts.earlyDataMax >> 8) & 0xff;
        ed[7] = opts.earlyDataMax & 0xff;
        extensions = ed;
    }

    const body = new Uint8Array(
        4 + 4 + 1 + nonce.length + 2 + ticket.length + 2 + extensions.length,
    );
    let o = 0;
    // ticket_lifetime
    body[o++] = (lifetime >> 24) & 0xff;
    body[o++] = (lifetime >> 16) & 0xff;
    body[o++] = (lifetime >> 8) & 0xff;
    body[o++] = lifetime & 0xff;
    // ticket_age_add
    body[o++] = (ageAdd >> 24) & 0xff;
    body[o++] = (ageAdd >> 16) & 0xff;
    body[o++] = (ageAdd >> 8) & 0xff;
    body[o++] = ageAdd & 0xff;
    // ticket_nonce
    body[o++] = nonce.length & 0xff;
    body.set(nonce, o); o += nonce.length;
    // ticket
    body[o++] = (ticket.length >> 8) & 0xff;
    body[o++] = ticket.length & 0xff;
    body.set(ticket, o); o += ticket.length;
    // extensions
    body[o++] = (extensions.length >> 8) & 0xff;
    body[o++] = extensions.length & 0xff;
    body.set(extensions, o);
    return body;
}

describe("SessionCache", () => {
    it("stores and retrieves a ticket by server name", () => {
        const cache = new SessionCache();
        const ticket: ResumptionTicket = {
            ticket: new Uint8Array(4).fill(0x01),
            ticketAgeAdd: 100,
            maxEarlyDataSize: 0,
            psk: new Uint8Array(32),
            cipherSuite: CIPHER_SUITE,
            receivedAt: 0,
        };
        cache.store("example.com", ticket);
        expect(cache.has("example.com")).toBe(true);
        expect(cache.get("example.com")).toBe(ticket);
    });

    it("returns undefined for an unknown server name", () => {
        const cache = new SessionCache();
        expect(cache.get("unknown.com")).toBeUndefined();
        expect(cache.has("unknown.com")).toBe(false);
    });

    it("deletes a stored ticket", () => {
        const cache = new SessionCache();
        cache.store("example.com", {
            ticket: new Uint8Array(0), ticketAgeAdd: 0, maxEarlyDataSize: 0,
            psk: new Uint8Array(0), cipherSuite: CIPHER_SUITE, receivedAt: 0,
        });
        expect(cache.size).toBe(1);
        cache.delete("example.com");
        expect(cache.has("example.com")).toBe(false);
        expect(cache.size).toBe(0);
    });

    it("clears all stored tickets", () => {
        const cache = new SessionCache();
        cache.store("a.com", {
            ticket: new Uint8Array(0), ticketAgeAdd: 0, maxEarlyDataSize: 0,
            psk: new Uint8Array(0), cipherSuite: CIPHER_SUITE, receivedAt: 0,
        });
        cache.store("b.com", {
            ticket: new Uint8Array(0), ticketAgeAdd: 0, maxEarlyDataSize: 0,
            psk: new Uint8Array(0), cipherSuite: CIPHER_SUITE, receivedAt: 0,
        });
        expect(cache.size).toBe(2);
        cache.clear();
        expect(cache.size).toBe(0);
    });

    it("overwrites the previous ticket for the same server name", () => {
        const cache = new SessionCache();
        const t1: ResumptionTicket = {
            ticket: new Uint8Array([1]), ticketAgeAdd: 1, maxEarlyDataSize: 0,
            psk: new Uint8Array(32).fill(1), cipherSuite: CIPHER_SUITE, receivedAt: 1,
        };
        const t2: ResumptionTicket = {
            ticket: new Uint8Array([2]), ticketAgeAdd: 2, maxEarlyDataSize: 0,
            psk: new Uint8Array(32).fill(2), cipherSuite: CIPHER_SUITE, receivedAt: 2,
        };
        cache.store("example.com", t1);
        cache.store("example.com", t2);
        expect(cache.size).toBe(1);
        expect(cache.get("example.com")).toBe(t2);
    });
});

describe("parseNewSessionTicket", () => {
    it("parses a well-formed ticket and derives a PSK", () => {
        const body = buildTicketBody({
            ticketAgeAdd: 0xdeadbeef,
            ticketNonce: new Uint8Array([0x42]),
            ticket: new Uint8Array(16).fill(0xcd),
        });
        const result = parseNewSessionTicket(
            body,
            new Uint8Array(32).fill(0x01), // masterSecret
            [new Uint8Array(10)], // transcript
            "SHA-256",
            CIPHER_SUITE,
            "example.com",
            1000,
            crypto,
        );
        expect(result).toBeDefined();
        expect(result!.serverName).toBe("example.com");
        expect(result!.ticket.ticket).toEqual(new Uint8Array(16).fill(0xcd));
        expect(result!.ticket.ticketAgeAdd).toBe(0xdeadbeef);
        expect(result!.ticket.maxEarlyDataSize).toBe(0);
        expect(result!.ticket.psk.length).toBe(32); // SHA-256 hash length
        expect(result!.ticket.cipherSuite).toBe(CIPHER_SUITE);
        expect(result!.ticket.receivedAt).toBe(1000);
    });

    it("extracts max_early_data_size from the early_data extension", () => {
        const body = buildTicketBody({ earlyDataMax: 16384 });
        const result = parseNewSessionTicket(
            body, new Uint8Array(32), [new Uint8Array(10)],
            "SHA-256", CIPHER_SUITE, "example.com", 0, crypto,
        );
        expect(result).toBeDefined();
        expect(result!.ticket.maxEarlyDataSize).toBe(16384);
    });

    it("derives a 48-byte PSK for SHA-384 cipher suites", () => {
        const body = buildTicketBody();
        const result = parseNewSessionTicket(
            body, new Uint8Array(48), [new Uint8Array(10)],
            "SHA-384", "TLS_AES_256_GCM_SHA384", "example.com", 0, crypto,
        );
        expect(result).toBeDefined();
        expect(result!.ticket.psk.length).toBe(48); // SHA-384 hash length
    });

    it("returns undefined when the body is too short (< 8 bytes)", () => {
        expect(parseNewSessionTicket(
            new Uint8Array(7), new Uint8Array(32), [new Uint8Array(10)],
            "SHA-256", CIPHER_SUITE, "example.com", 0, crypto,
        )).toBeUndefined();
    });

    it("returns undefined when the ticket_nonce is truncated", () => {
        // Build a body where the nonce length says 10 but only 2 bytes follow.
        const body = new Uint8Array(8 + 1 + 2); // lifetime(4) + ageAdd(4) + nonceLen(1) + 2 bytes
        body[8] = 10; // nonce length = 10, but only 2 bytes available
        expect(parseNewSessionTicket(
            body, new Uint8Array(32), [new Uint8Array(10)],
            "SHA-256", CIPHER_SUITE, "example.com", 0, crypto,
        )).toBeUndefined();
    });

    it("returns undefined when the ticket body is truncated", () => {
        // Build a body where the ticket length says 100 but only 4 bytes follow.
        const body = new Uint8Array(8 + 1 + 0 + 2 + 4); // lifetime(4) + ageAdd(4) + nonce(1+0) + ticketLen(2) + 4 bytes
        body[8] = 0; // nonce length = 0
        body[9] = 0; body[10] = 100; // ticket length = 100, but only 4 bytes
        expect(parseNewSessionTicket(
            body, new Uint8Array(32), [new Uint8Array(10)],
            "SHA-256", CIPHER_SUITE, "example.com", 0, crypto,
        )).toBeUndefined();
    });

    it("produces different PSKs for different ticket nonces", () => {
        const body1 = buildTicketBody({ ticketNonce: new Uint8Array([0x01]) });
        const body2 = buildTicketBody({ ticketNonce: new Uint8Array([0x02]) });
        const masterSecret = new Uint8Array(32).fill(0x42);
        const transcript = [new Uint8Array(10)];
        const r1 = parseNewSessionTicket(body1, masterSecret, transcript, "SHA-256", CIPHER_SUITE, "a.com", 0, crypto);
        const r2 = parseNewSessionTicket(body2, masterSecret, transcript, "SHA-256", CIPHER_SUITE, "a.com", 0, crypto);
        expect(r1).toBeDefined();
        expect(r2).toBeDefined();
        expect(r1!.ticket.psk).not.toEqual(r2!.ticket.psk);
    });
});
