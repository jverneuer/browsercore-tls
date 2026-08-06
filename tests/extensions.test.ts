/**
 * Tests for @browsercore/tls extensions (RFC 8446 §4.2, RFC 6066).
 *
 * Covers the parser (happy path + every malformed-input branch), the wire
 * encoders/decoders for signature schemes and named groups, and findExtension.
 */

import { describe, it, expect } from "vitest";
import {
    ExtensionType,
    parseExtensions,
    findExtension,
    signatureSchemeToWire,
    namedGroupToWire,
    wireToNamedGroup,
    wireToExtensionType,
} from "../src/extensions/extensions.js";
import { TlsHandshakeError } from "../src/errors.js";
import type { NamedGroup, SignatureScheme } from "../src/types.js";

/** Serialize one extension: type(2) || data_len(2) || data. */
function ext(type: ExtensionType, data: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + 2 + data.length);
    out[0] = (type >> 8) & 0xff;
    out[1] = type & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out[3] = data.length & 0xff;
    out.set(data, 4);
    return out;
}

/** Wrap a list of serialized extensions under the 2-byte length prefix. */
function extensionsBlock(...extensions: readonly Uint8Array[]): Uint8Array {
    let total = 0;
    for (const e of extensions) {
        total += e.length;
    }
    const out = new Uint8Array(2 + total);
    out[0] = (total >> 8) & 0xff;
    out[1] = total & 0xff;
    let o = 2;
    for (const e of extensions) {
        out.set(e, o);
        o += e.length;
    }
    return out;
}

describe("parseExtensions", () => {
    it("parses a block with multiple extensions", () => {
        const a = ext(ExtensionType.SUPPORTED_VERSIONS, new Uint8Array([0x03, 0x04]));
        const b = ext(ExtensionType.KEY_SHARE, new Uint8Array([0x00, 0x1d, 0x00, 0x01, 0x42]));
        const block = extensionsBlock(a, b);
        const parsed = parseExtensions(block);
        expect(parsed).toHaveLength(2);
        expect(parsed[0]!.type).toBe(ExtensionType.SUPPORTED_VERSIONS);
        expect(parsed[0]!.data).toEqual(new Uint8Array([0x03, 0x04]));
        expect(parsed[1]!.type).toBe(ExtensionType.KEY_SHARE);
        expect(parsed[1]!.data).toEqual(new Uint8Array([0x00, 0x1d, 0x00, 0x01, 0x42]));
    });

    it("parses an empty extensions block", () => {
        const block = new Uint8Array([0x00, 0x00]);
        expect(parseExtensions(block)).toEqual([]);
    });

    it("throws TlsHandshakeError when the buffer is shorter than the 2-byte length prefix", () => {
        expect(() => parseExtensions(new Uint8Array([0x00]))).toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError when the length prefix exceeds the buffer", () => {
        // extensions_len says 10 bytes follow, but only 2 do.
        const block = new Uint8Array([0x00, 0x0a, 0x00, 0x2b]);
        expect(() => parseExtensions(block)).toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError when an extension header is truncated", () => {
        // extensions_len = 3, buffer is exactly 2 + 3 = 5 bytes (outer check
        // passes), but reading the 4-byte extension header needs o + 4 = 6 > end = 5.
        const block = new Uint8Array([0x00, 0x03, 0x00, 0x2b, 0x00]);
        try {
            parseExtensions(block);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/extension header truncated/);
        }
    });

    it("throws TlsHandshakeError when extension data is truncated", () => {
        // extensions_len = 6, buffer is exactly 2 + 6 = 8 bytes (outer check
        // passes). One extension: type=43, data_len=4, but only 2 bytes of data
        // present, so o + dataLen = 6 + 4 = 10 > end = 8.
        const block = new Uint8Array([0x00, 0x06, 0x00, 0x2b, 0x00, 0x04, 0x03, 0x00]);
        try {
            parseExtensions(block);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/extension data truncated/);
        }
    });
});

describe("findExtension", () => {
    it("finds the first extension of the requested type", () => {
        const block = extensionsBlock(
            ext(ExtensionType.SERVER_NAME, new Uint8Array([0x00])),
            ext(ExtensionType.SUPPORTED_VERSIONS, new Uint8Array([0x03, 0x04])),
        );
        const parsed = parseExtensions(block);
        const found = findExtension(parsed, ExtensionType.SUPPORTED_VERSIONS);
        expect(found).toBeDefined();
        expect(found!.data).toEqual(new Uint8Array([0x03, 0x04]));
    });

    it("returns undefined when the requested type is absent", () => {
        const block = extensionsBlock(ext(ExtensionType.SERVER_NAME, new Uint8Array([0x00])));
        const parsed = parseExtensions(block);
        expect(findExtension(parsed, ExtensionType.SUPPORTED_VERSIONS)).toBeUndefined();
    });
});

describe("signatureSchemeToWire", () => {
    it("maps every advertised signature scheme to its IANA wire value", () => {
        const cases: ReadonlyArray<[SignatureScheme, number]> = [
            ["ecdsa_secp256r1_sha256", 0x0403],
            ["ecdsa_secp384r1_sha384", 0x0503],
            ["rsa_pss_rsae_sha256", 0x0804],
            ["rsa_pss_rsae_sha384", 0x0805],
            ["rsa_pkcs1_sha256", 0x0401],
        ];
        for (const [scheme, wire] of cases) {
            expect(signatureSchemeToWire(scheme)).toBe(wire);
        }
    });
});

describe("namedGroupToWire", () => {
    it("maps every named group to its IANA wire value", () => {
        const cases: ReadonlyArray<[NamedGroup, number]> = [
            ["secp256r1", 0x0017],
            ["secp384r1", 0x0018],
            ["x25519", 0x001d],
            ["x448", 0x001e],
            ["X25519MLKEM768", 0x11ec],
            ["X25519Kyber768", 0x6399],
        ];
        for (const [group, wire] of cases) {
            expect(namedGroupToWire(group)).toBe(wire);
        }
    });
});

describe("wireToNamedGroup", () => {
    it("inverts every IANA wire value to its named group", () => {
        expect(wireToNamedGroup(0x0017)).toBe("secp256r1");
        expect(wireToNamedGroup(0x0018)).toBe("secp384r1");
        expect(wireToNamedGroup(0x0019)).toBe("secp521r1");
        expect(wireToNamedGroup(0x001d)).toBe("x25519");
        expect(wireToNamedGroup(0x001e)).toBe("x448");
        expect(wireToNamedGroup(0x11ec)).toBe("X25519MLKEM768");
        expect(wireToNamedGroup(0x6399)).toBe("X25519Kyber768");
    });

    it("throws TlsHandshakeError for an unsupported wire value", () => {
        expect(() => wireToNamedGroup(0x0099)).toThrow(TlsHandshakeError);
        try {
            wireToNamedGroup(0x0099);
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/unsupported named group/);
        }
    });

    it("round-trips every named group through namedGroupToWire and wireToNamedGroup", () => {
        const groups: readonly NamedGroup[] = [
            "secp256r1",
            "secp384r1",
            "secp521r1",
            "x25519",
            "x448",
            "X25519MLKEM768",
            "X25519Kyber768",
        ];
        for (const group of groups) {
            expect(wireToNamedGroup(namedGroupToWire(group))).toBe(group);
        }
    });
});

describe("wireToExtensionType (chrome-140 new types)", () => {
    it("accepts application_settings at the renumbered value 17613", () => {
        expect(() => wireToExtensionType(17613)).not.toThrow();
        expect(wireToExtensionType(17613)).toBe(ExtensionType.APPLICATION_SETTINGS);
    });

    it("accepts application_settings_old at the legacy value 17513", () => {
        expect(() => wireToExtensionType(17513)).not.toThrow();
        expect(wireToExtensionType(17513)).toBe(ExtensionType.APPLICATION_SETTINGS_OLD);
    });

    it("accepts encrypted_client_hello at 65037", () => {
        expect(() => wireToExtensionType(65037)).not.toThrow();
        expect(wireToExtensionType(65037)).toBe(ExtensionType.ENCRYPTED_CLIENT_HELLO);
    });

    it("accepts padding (RFC 7685) at 21", () => {
        expect(() => wireToExtensionType(21)).not.toThrow();
        expect(wireToExtensionType(21)).toBe(ExtensionType.PADDING);
    });
});

describe("parseExtensions byte-truncation guard", () => {
    it("throws when reading an extension byte past the end of the buffer", () => {
        // extensions_len = 10, so the outer `o + extensionsLen > buf.length`
        // check (line 87) looks at o=2: 2 + 10 = 12 > 4 → this throws there.
        // To reach the inner readByte byte===undefined guard we need a buffer
        // where the length prefix passes the outer check but a sub-read runs
        // past the end: extensions_len=2, exactly 2 trailing bytes → the header
        // read consumes them, then the data-len read in the loop goes past.
        // Layout: extensions_len=2, then a 2-byte extension (type only, no
        // data_len/data). Reading data_len at o=4 reads buf[4],[5] = undefined.
        const block = new Uint8Array([0x00, 0x02, 0x00, 0x2b]);
        try {
            parseExtensions(block);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
        }
    });
});

describe("wireToExtensionType (parseExtensions unknown type)", () => {
    it("rejects an extension whose type wire value is unknown", () => {
        // A single extension of type 0x0099 (not a legal ExtensionType) with a
        // 1-byte body. parseExtensions decodes it via wireToExtensionType, which
        // must reject the unknown type rather than smuggle it through as a
        // number.
        const ext = new Uint8Array([0x00, 0x99, 0x00, 0x01, 0x42]);
        const total = ext.length;
        const block = new Uint8Array(2 + total);
        block[0] = (total >> 8) & 0xff;
        block[1] = total & 0xff;
        block.set(ext, 2);
        try {
            parseExtensions(block);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/unsupported extension type/);
        }
    });
});

describe("unknown value guards (table lookup miss)", () => {
    it("signatureSchemeToWire throws on an unrecognised scheme", () => {
        const bogus = "md5_with_rsa" as unknown as SignatureScheme;
        expect(() => signatureSchemeToWire(bogus)).toThrow(/unknown signature scheme/);
    });

    it("namedGroupToWire throws on an unrecognised group", () => {
        const bogus = "frobnitz" as unknown as NamedGroup;
        expect(() => namedGroupToWire(bogus)).toThrow(/unknown named group/);
    });
});

