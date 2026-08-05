/**
 * Targeted coverage for the uncovered branches in handshake/server-hello.ts
 * and extensions/extensions.ts.
 *
 * server-hello.ts gaps:
 *   - wireToCipherSuite: the TLS_CHACHA20_POLY1305_SHA256 (0x1303) case and the
 *     TLS_AES_128_CCM_SHA256 (0x1304) case
 *   - readByte: the `byte === undefined` noUncheckedIndexedAccess guard
 *   - negotiateVersion: the `hi === undefined || lo === undefined` guard
 *
 * extensions.ts gaps:
 *   - signatureSchemeToWire: ed25519, rsa_pss_rsae_sha512, rsa_pkcs1_sha384,
 *     rsa_pkcs1_sha512, rsa_pkcs1_sha51 (all untested enum members)
 *   - parseExtensions: the inner readByte `byte === undefined` guard
 *   - wireToExtensionType: GREASE sentinel acceptance (the `isGreaseValue`
 *     default branch)
 */

import { describe, it, expect } from "vitest";
import {
    parseServerHello,
    type ServerHelloValidation,
} from "../src/handshake/server-hello.js";
import {
    ExtensionType,
    parseExtensions,
    signatureSchemeToWire,
    wireToExtensionType,
} from "../src/extensions/extensions.js";
import { TlsHandshakeError } from "../src/errors.js";
import { TLS_1_3, type SignatureScheme } from "../src/types.js";

const OFFERED: ServerHelloValidation = {
    cipherSuites: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
    ],
    supportedVersions: [TLS_1_3],
};

/**
 * Build a ServerHello body from its logical fields. Mirrors the helper in
 * tests/server-hello.test.ts but lives here so this file stays self-contained.
 */
function buildServerHelloBody(opts: {
    cipherSuite?: number;
    compression?: number;
    sessionId?: Uint8Array;
    versionWire?: number;
} = {}): Uint8Array {
    const random = new Uint8Array(32).fill(0x5a);
    const sessionId = opts.sessionId ?? new Uint8Array(0);
    const cipherSuite = opts.cipherSuite ?? 0x1301;
    const compression = opts.compression ?? 0x00;
    const versionWire = opts.versionWire ?? TLS_1_3.wire;

    const svData = new Uint8Array([(versionWire >> 8) & 0xff, versionWire & 0xff]);
    const svExt = new Uint8Array(2 + 2 + svData.length);
    svExt[0] = (ExtensionType.SUPPORTED_VERSIONS >> 8) & 0xff;
    svExt[1] = ExtensionType.SUPPORTED_VERSIONS & 0xff;
    svExt[2] = (svData.length >> 8) & 0xff;
    svExt[3] = svData.length & 0xff;
    svExt.set(svData, 4);

    const body = new Uint8Array(2 + 32 + 1 + sessionId.length + 2 + 1 + 2 + svExt.length);
    let o = 0;
    body[o++] = 0x03;
    body[o++] = 0x03;
    body.set(random, o);
    o += 32;
    body[o++] = sessionId.length;
    body.set(sessionId, o);
    o += sessionId.length;
    body[o++] = (cipherSuite >> 8) & 0xff;
    body[o++] = cipherSuite & 0xff;
    body[o++] = compression;
    body[o++] = (svExt.length >> 8) & 0xff;
    body[o++] = svExt.length & 0xff;
    body.set(svExt, o);
    return body;
}

/**
 * Wrap a Uint8Array in a Proxy that returns `undefined` for every numeric
 * index >= truncFrom. This exercises noUncheckedIndexedAccess guards (the
 * `byte === undefined` branches) which are unreachable with a real Uint8Array
 * but still appear in v8 branch coverage. Methods like `subarray`, `set`, and
 * the iterator are forwarded so the parsed data is otherwise genuine.
 *
 * `subarray` returns a new proxy whose truncation semantics follow the parent:
 * if the parent truncates at N, a subarray starting at `from` truncates its
 * own indexes at `max(0, N - from)` — which keeps the sentinel in sync so the
 * `hi === undefined || lo === undefined` guard in negotiateVersion fires when
 * reading the supported_versions extension's 2-byte body.
 */
function withTruncatedIndexes(buf: Uint8Array, truncFrom: number): Uint8Array {
    const target = buf;
    const proxy = new Proxy(target, {
        get(t, prop, receiver) {
            if (typeof prop === "string" && /^\d+$/u.test(prop)) {
                const idx = Number(prop);
                if (idx >= truncFrom) {
                    // oxlint-disable-next-line unicorn/no-useless-undefined
                    return undefined;
                }
                // oxlint-disable-next-line typescript/no-non-null-assertion — bounds checked above.
                return t[idx]!;
            }
            if (prop === "length") {
                return t.length;
            }
            if (prop === "subarray") {
                return (from: number, end?: number): Uint8Array => {
                    const endIdx = end ?? t.length;
                    const sliced = t.subarray(from, endIdx);
                    const childTrunc = from >= truncFrom ? 0 : Math.max(0, truncFrom - from);
                    return withTruncatedIndexes(sliced, childTrunc);
                };
            }
            if (prop === "set") {
                return (...args: Parameters<Uint8Array["set"]>): void => {
                    t.set(...args);
                };
            }
            if (prop === Symbol.iterator) {
                return (): IterableIterator<number> => t[Symbol.iterator]();
            }
            return Reflect.get(t, prop, receiver) as unknown;
        },
    });
    return proxy as Uint8Array;
}

describe("wireToCipherSuite — TLS_CHACHA20_POLY1305_SHA256 and AES_128_CCM cases", () => {
    it("parses a ServerHello that negotiates CHACHA20_POLY1305 (0x1303)", () => {
        const body = buildServerHelloBody({ cipherSuite: 0x1303 });
        const hello = parseServerHello(body, OFFERED);
        expect(hello.cipherSuite).toBe("TLS_CHACHA20_POLY1305_SHA256");
    });

    it("parses a ServerHello that negotiates AES_128_CCM (0x1304)", () => {
        const body = buildServerHelloBody({ cipherSuite: 0x1304 });
        const hello = parseServerHello(body, OFFERED);
        expect(hello.cipherSuite).toBe("TLS_AES_128_CCM_SHA256");
    });
});

describe("readByte byte-truncation guard (server-hello.ts line 84)", () => {
    it("throws when the first readByte indexes past the buffer's contents", () => {
        const realBody = buildServerHelloBody();
        const fake = withTruncatedIndexes(realBody, 0);
        try {
            parseServerHello(fake, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/byte truncated/u);
        }
    });
});

describe("negotiateVersion hi/lo truncation guard (server-hello.ts line 151)", () => {
    it("throws when supported_versions data bytes read as undefined", () => {
        const realBody = buildServerHelloBody();

        // Body layout: version(2) + random(32) + sid_len(1) + sid(0) + cs(2) +
        // comp(1) + ext_len(2) + ext(type2+len2+data2). The supported_versions
        // data starts at offset 44.
        const svDataOffset = 2 + 32 + 1 + 0 + 2 + 1 + 2 + 4;
        expect(svDataOffset).toBeLessThan(realBody.length);

        const fake = withTruncatedIndexes(realBody, svDataOffset);

        try {
            parseServerHello(fake, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/data truncated/u);
        }
    });
});

describe("signatureSchemeToWire — untested enum members", () => {
    it("maps ed25519 to 0x0807", () => {
        expect(signatureSchemeToWire("ed25519")).toBe(0x0807);
    });

    it("maps rsa_pss_rsae_sha512 to 0x0806", () => {
        expect(signatureSchemeToWire("rsa_pss_rsae_sha512")).toBe(0x0806);
    });

    it("maps rsa_pkcs1_sha384 to 0x0501", () => {
        expect(signatureSchemeToWire("rsa_pkcs1_sha384")).toBe(0x0501);
    });

    it("maps rsa_pkcs1_sha512 to 0x0601", () => {
        expect(signatureSchemeToWire("rsa_pkcs1_sha512")).toBe(0x0601);
    });

    it("maps rsa_pkcs1_sha1 to 0x0201", () => {
        expect(signatureSchemeToWire("rsa_pkcs1_sha1")).toBe(0x0201);
    });

    it("covers every SignatureScheme member", () => {
        const schemes: readonly SignatureScheme[] = [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ed25519",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ];
        const wires = schemes.map((s) => signatureSchemeToWire(s));
        // No duplicates — each scheme has a distinct IANA value.
        expect(new Set(wires).size).toBe(schemes.length);
    });
});

describe("parseExtensions inner byte-truncation guard", () => {
    it("throws when an inner readByte indexes past the buffer's contents", () => {
        const real = new Uint8Array([0x00, 0x04, 0x00, 0x2b, 0x00, 0x01, 0x42]);
        const fake = withTruncatedIndexes(real, 0);
        try {
            parseExtensions(fake);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/extension byte truncated/u);
        }
    });
});

describe("wireToExtensionType — GREASE sentinels are tolerated", () => {
    it("returns GREASE values as-is instead of throwing", () => {
        expect(wireToExtensionType(0x0a0a)).toBe(0x0a0a);
        expect(wireToExtensionType(0x1a1a)).toBe(0x1a1a);
        expect(wireToExtensionType(0x2a2a)).toBe(0x2a2a);
        expect(wireToExtensionType(0x3a3a)).toBe(0x3a3a);
        expect(wireToExtensionType(0x4a4a)).toBe(0x4a4a);
        expect(wireToExtensionType(0x5a5a)).toBe(0x5a5a);
        expect(wireToExtensionType(0x6a6a)).toBe(0x6a6a);
        expect(wireToExtensionType(0x7a7a)).toBe(0x7a7a);
        expect(wireToExtensionType(0x8a8a)).toBe(0x8a8a);
        expect(wireToExtensionType(0x9a9a)).toBe(0x9a9a);
        expect(wireToExtensionType(0xaaaa)).toBe(0xaaaa);
        expect(wireToExtensionType(0xbaba)).toBe(0xbaba);
        expect(wireToExtensionType(0xcaca)).toBe(0xcaca);
        expect(wireToExtensionType(0xdada)).toBe(0xdada);
        expect(wireToExtensionType(0xeaea)).toBe(0xeaea);
        expect(wireToExtensionType(0xfafa)).toBe(0xfafa);
    });

    it("rejects a non-GREASE, non-standard extension type", () => {
        try {
            wireToExtensionType(0x0099);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/unsupported extension type/u);
        }
    });
});
