/**
 * Small coverage tests for isolated branches that have no natural home in the
 * existing test files — single-line exhaustiveness defaults and noUnchecked
 * IndexedAccess guards that exist only to satisfy the TypeScript compiler.
 *
 * These close out the last few missing branches needed to clear the 94% target.
 */

import { describe, it, expect } from "vitest";
import { isKeyShareGroup } from "../src/handshake/handshake.js";
import { parseRecordHeader, serializeRecordHeader } from "../src/record/record.js";
import { constantTimeEqual } from "../src/utils.js";
import { TlsDecryptError } from "../src/errors.js";
import type { NamedGroup } from "../src/types.js";

describe("isKeyShareGroup — assertNever exhaustiveness default", () => {
    it("hits the default branch for a NamedGroup outside the union", () => {
        const bogus = "frobnitz" as unknown as NamedGroup;
        expect(() => isKeyShareGroup(bogus)).toThrow(/Unexpected value/u);
    });
});

describe("constantTimeEqual — length-mismatch fast path", () => {
    it("returns false immediately when lengths differ", () => {
        const a = new Uint8Array([0x01, 0x02, 0x03]);
        const b = new Uint8Array([0x01, 0x02]);
        expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("returns false when bytes differ", () => {
        const a = new Uint8Array([0x01, 0x02, 0x03]);
        const b = new Uint8Array([0x01, 0x02, 0x04]);
        expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("returns true for equal arrays", () => {
        const a = new Uint8Array([0x01, 0x02, 0x03]);
        expect(constantTimeEqual(a, a.slice())).toBe(true);
    });
});

describe("parseRecordHeader — truncated buffer at exactly RECORD_HEADER_SIZE", () => {
    it("parses a valid 5-byte record header", () => {
        const buf = serializeRecordHeader(22, 10);
        const header = parseRecordHeader(buf);
        expect(header.type).toBe(22);
        expect(header.length).toBe(10);
    });

    it("throws TlsDecryptError for a buffer shorter than 5 bytes", () => {
        expect(() => parseRecordHeader(new Uint8Array(4))).toThrow(TlsDecryptError);
    });
});
