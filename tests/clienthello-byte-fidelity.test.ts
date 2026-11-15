/**
 * Byte-fidelity tests for the 2026-11-15 fingerprint-diagnosis fixes (0.4.14):
 *
 *   D6  — the key_share GREASE entry is a 1-byte 0x00 payload (was 32 random
 *         bytes, an X25519-sized blob real Chrome never sends).
 *   D6b — supported_groups advertises a list INDEPENDENT of the key-share list
 *         when `supportedGroups` is configured; absent it, it derives from
 *         `keyShareGroups` (backwards compatible).
 *   D7  — every GREASE slot (cipher head, leading ext, key_share group,
 *         supported_groups head, supported_versions head, trailing ext) carries
 *         an INDEPENDENTLY drawn 0x?a?a sentinel, and the trailing GREASE
 *         extension body is one 0x00 byte (was empty).
 *   D8  — the INITIAL ClientHello record carries legacy version 0x0301; the
 *         ClientHello_2 record after an HRR stays 0x0303 (RFC 8446 §5.1).
 *   D9  — ALPS advertises ONLY "h2" (5-byte body `00 03 02 68 32`), and is
 *         omitted entirely when the ALPN list has no h2.
 *
 * Ground truth: golden chrome-131 capture
 * (browsercore-testing captures/chrome-131/tls/client_hello.bin):
 *   record    `16 03 01 …`
 *   ciphers   `5a5a 1301 1302 …`
 *   ext head  `4a4a 0000 …` (leading GREASE ext, empty body)
 *   key_share `caca 0001 00 | 0011ec 04c0 <1216B> | 001d 0020 <32B>`
 *   groups    `000a 000c 0aca ca11 ec00 1d00 1700 18` (advertises secp256r1 +
 *             secp384r1 which are NOT key-shared)
 *   versions  `002b 0007 06 4a4a 0304 0303`
 *   ALPS      `4469 0005 0003 0268 32` (h2-only, 5B)
 *   tail      `… 5a5a 0001 00` (trailing GREASE ext, 1-byte 0x00 body)
 */

import { describe, it, expect } from "vitest";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import { buildClientHello } from "../src/handshake/client-hello.js";
import { connectTls } from "../src/tls.js";
import { CLIENT_HELLO_RECORD_VERSION, ContentType } from "../src/record/record.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, KeyPair, NamedGroup } from "../src/types.js";
import { FakeTransport } from "./fake-transport.js";
import { TlsServerSim } from "./server-sim.js";

/** Parse the offered cipher suites from a serialized ClientHello. */
function parseCipherSuites(hello: Uint8Array): readonly number[] {
    let o = 4 + 2 + 32; // handshake header + version + random
    o += 1 + (hello[o] ?? 0); // session id
    const csLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2;
    const suites: number[] = [];
    for (let i = 0; i < csLen; i += 2) {
        suites.push(((hello[o + i] ?? 0) << 8) | (hello[o + i + 1] ?? 0));
    }
    return suites;
}

/** Parse the extensions block into ordered { type, data } records. */
function parseExtensions(hello: Uint8Array): ReadonlyArray<{ type: number; data: Uint8Array }> {
    let o = 4 + 2 + 32;
    o += 1 + (hello[o] ?? 0); // session id
    o += 2 + (((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0)); // cipher suites
    o += 1 + (hello[o] ?? 0); // compression
    const extLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2;
    const end = o + extLen;
    const out: { type: number; data: Uint8Array }[] = [];
    while (o < end) {
        const type = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
        const dataLen = ((hello[o + 2] ?? 0) << 8) | (hello[o + 3] ?? 0);
        out.push({ type, data: hello.subarray(o + 4, o + 4 + dataLen) });
        o += 4 + dataLen;
    }
    return out;
}

/** A config exercising every GREASE slot (cipher, exts, groups, versions). */
function greasedConfig(): ClientHelloConfig {
    return {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: [
            ExtensionType.SUPPORTED_GROUPS, // 10
            ExtensionType.SUPPORTED_VERSIONS, // 43
            ExtensionType.KEY_SHARE, // 51
        ],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        grease: true,
    };
}

/** Fake x25519 key pairs for the requested group names. */
function fakeKeyPairs(groups: readonly KeyPair["algorithm"][]): readonly KeyPair[] {
    return groups.map((algorithm) => ({
        algorithm,
        privateKey: new Uint8Array(32),
        publicKey: new Uint8Array(32).fill(0xab),
    }));
}

/**
 * Deterministic sequenced random source. drawGreaseSentinels consumes draws in
 * a fixed slot order (cipher, leading ext, key_share group, supported_groups,
 * supported_versions, trailing ext), so feeding i/16 puts sentinel i in slot i:
 * 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a — all distinct, mirroring the
 * golden capture's per-slot independence (5a5a/4a4a/caca).
 */
function sequencedRandom(drawCount: number): () => number {
    let draws = 0;
    return () => {
        const value = draws < drawCount ? draws / 16 : 0;
        draws++;
        return value;
    };
}

describe("D6: key_share GREASE entry is 1 byte of 0x00", () => {
    it("encodes group=<sentinel> key_length=1 payload=0x00 ahead of the real shares", async () => {
        const kp = crypto.x25519GenerateKeyPair();
        const kps: readonly KeyPair[] = [{ algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey }];
        const hello = buildClientHello(greasedConfig(), kps, () => 0.0, crypto);
        const ks = parseExtensions(hello).find((e) => e.type === ExtensionType.KEY_SHARE)!;
        // Body: client_shares_len(2) || entries. First entry must be exactly the
        // golden shape `caca 0001 00` (here sentinel 0x0a0a from random()=0.0).
        expect(Array.from(ks.data.subarray(2, 9))).toEqual([
            0x0a, 0x0a, // GREASE group (this slot's own sentinel)
            0x00, 0x01, // key_length = 1
            0x00, // single zero payload byte
            0x00, 0x1d, // first REAL group: x25519
        ]);
    });
});

describe("D7: every GREASE slot draws an independent sentinel", () => {
    it("uses a distinct sentinel per slot (cipher, exts, groups, versions)", async () => {
        const hello = buildClientHello(
            greasedConfig(),
            fakeKeyPairs(["x25519"]),
            sequencedRandom(6),
            crypto,
        );

        const suites = parseCipherSuites(hello);
        const extensions = parseExtensions(hello);
        const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE)!;
        const sg = extensions.find((e) => e.type === ExtensionType.SUPPORTED_GROUPS)!;
        const sv = extensions.find((e) => e.type === ExtensionType.SUPPORTED_VERSIONS)!;

        const slotValues = {
            cipherSuite: suites[0]!,
            leadingExtension: extensions[0]!.type,
            keyShareGroup: ((ks.data[2] ?? 0) << 8) | (ks.data[3] ?? 0),
            supportedGroups: ((sg.data[2] ?? 0) << 8) | (sg.data[3] ?? 0),
            supportedVersions: ((sv.data[1] ?? 0) << 8) | (sv.data[2] ?? 0),
            trailingExtension: extensions[extensions.length - 1]!.type,
        };

        // One distinct draw per slot, in the documented draw order — the real
        // Chrome structure (golden: cipher 0x5a5a, ext 0x4a4a, keyshare/groups
        // 0xcaca — equalities between slots are coincidence, never structure).
        expect(slotValues).toEqual({
            cipherSuite: 0x0a0a,
            leadingExtension: 0x1a1a,
            keyShareGroup: 0x2a2a,
            supportedGroups: 0x3a3a,
            supportedVersions: 0x4a4a,
            trailingExtension: 0x5a5a,
        });
        // Statistical structure: NOT all equal (a single reused sentinel is the
        // old, fingerprint-divergent behavior).
        expect(new Set(Object.values(slotValues)).size).toBe(6);
    });

    it("the trailing GREASE extension body is a single 0x00 byte", async () => {
        const hello = buildClientHello(greasedConfig(), fakeKeyPairs(["x25519"]), sequencedRandom(6), crypto);
        const trailing = parseExtensions(hello).at(-1)!;
        expect(trailing.type).toBe(0x5a5a);
        // Golden chrome-131 tail: `5a5a 0001 00` — 1-byte body, not empty.
        expect(Array.from(trailing.data)).toEqual([0x00]);
    });

    it("the leading GREASE extension body stays empty", async () => {
        const hello = buildClientHello(greasedConfig(), fakeKeyPairs(["x25519"]), sequencedRandom(6), crypto);
        const leading = parseExtensions(hello)[0]!;
        expect(leading.type).toBe(0x1a1a);
        // Golden chrome-131: `4a4a 0000` — the LEADING GREASE ext has no body.
        expect(leading.data.length).toBe(0);
    });
});

describe("D6b: supported_groups advertises independently of key_share", () => {
    /** The advertised set for the split-list config (golden chrome-131 shape). */
    const ADVERTISED: readonly NamedGroup[] = ["X25519MLKEM768", "x25519", "secp256r1", "secp384r1"];

    /**
     * Build the split-list config. `advertised` sets `supportedGroups`; when
     * omitted the key is absent entirely (exactOptionalPropertyTypes-safe) so
     * the derive-from-keyShareGroups fallback can be exercised.
     */
    function splitConfig(advertised?: readonly NamedGroup[]): ClientHelloConfig {
        const base: ClientHelloConfig = {
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
            extensionOrder: [ExtensionType.SUPPORTED_GROUPS, ExtensionType.KEY_SHARE],
            // Real Chrome 131: shares GREASE+MLKEM768+x25519, but ADVERTISES
            // secp256r1+secp384r1 as well (golden groups list ends `0017 0018`).
            keyShareGroups: ["X25519MLKEM768", "x25519"],
            signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
            supportedVersions: [TLS_1_3],
            serverName: "example.com",
            grease: false,
        };
        return advertised === undefined
            ? base
            : { ...base, supportedGroups: advertised };
    }

    it("puts the advertised list on the wire when supportedGroups is set", () => {
        const hello = buildClientHello(splitConfig(ADVERTISED), fakeKeyPairs(["X25519MLKEM768", "x25519"]), () => 0, crypto);
        const extensions = parseExtensions(hello);
        const sg = extensions.find((e) => e.type === ExtensionType.SUPPORTED_GROUPS)!;
        // list_len=8, groups: 0x11ec | 0x001d | 0x0017 | 0x0018 — exactly the
        // golden's non-GREASE tail (`11ec 001d 0017 0018`).
        expect(Array.from(sg.data)).toEqual([0x00, 0x08, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
    });

    it("key_share still carries ONLY the shared groups (no secp256r1/secp384r1)", () => {
        const hello = buildClientHello(splitConfig(ADVERTISED), fakeKeyPairs(["X25519MLKEM768", "x25519"]), () => 0, crypto);
        const ks = parseExtensions(hello).find((e) => e.type === ExtensionType.KEY_SHARE)!;
        const groupsInShare: number[] = [];
        for (let o = 2; o < ks.data.length;) {
            groupsInShare.push(((ks.data[o] ?? 0) << 8) | (ks.data[o + 1] ?? 0));
            o += 2 + 2 + (((ks.data[o + 2] ?? 0) << 8) | (ks.data[o + 3] ?? 0));
        }
        // Golden key_share: GREASE | 0x11ec | 0x001d — the advertised-only
        // curves never appear here.
        expect(groupsInShare).toEqual([0x11ec, 0x001d]);
    });

    it("derives supported_groups from keyShareGroups when supportedGroups is absent (backwards compatible)", () => {
        const hello = buildClientHello(splitConfig(), fakeKeyPairs(["X25519MLKEM768", "x25519"]), () => 0, crypto);
        const sg = parseExtensions(hello).find((e) => e.type === ExtensionType.SUPPORTED_GROUPS)!;
        expect(Array.from(sg.data)).toEqual([0x00, 0x04, 0x11, 0xec, 0x00, 0x1d]);
    });

    it("injects the supported_groups slot's own GREASE sentinel when grease=true", () => {
        const cfg: ClientHelloConfig = { ...splitConfig(ADVERTISED), grease: true };
        // Draws: cipher(0x0a0a), leadExt(0x1a1a), ksGroup(0x2a2a), sgGroup(0x3a3a), …
        const hello = buildClientHello(cfg, fakeKeyPairs(["X25519MLKEM768", "x25519"]), sequencedRandom(6), crypto);
        const sg = parseExtensions(hello).find((e) => e.type === ExtensionType.SUPPORTED_GROUPS)!;
        expect(Array.from(sg.data)).toEqual([
            0x00, 0x0a, // list_len = 5 groups * 2
            0x3a, 0x3a, // this slot's OWN sentinel, not the key_share one
            0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        ]);
    });
});

describe("D9: ALPS advertises only h2", () => {
    function alpsConfig(alpnProtocols: readonly string[]): ClientHelloConfig {
        return {
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
            extensionOrder: [
                ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, // 16
                ExtensionType.APPLICATION_SETTINGS, // 17613
            ],
            keyShareGroups: ["x25519"],
            signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
            supportedVersions: [TLS_1_3],
            serverName: "example.com",
            alpnProtocols,
            grease: false,
        };
    }

    it("ALPS body is 5 bytes advertising only h2 while ALPN keeps the full list", () => {
        const hello = buildClientHello(alpsConfig(["h2", "http/1.1"]), fakeKeyPairs(["x25519"]), () => 0, crypto);
        const extensions = parseExtensions(hello);
        const alpn = extensions.find((e) => e.type === ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)!;
        const alps = extensions.find((e) => e.type === ExtensionType.APPLICATION_SETTINGS)!;
        // ALPN unchanged: full `000c 02'h2' 08'http/1.1'` (14B).
        expect(Array.from(alpn.data)).toEqual([
            0x00, 0x0c, 0x02, 0x68, 0x32, 0x08,
            0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
        ]);
        // ALPS h2-only: golden chrome-131 sends `4469 0005 0003 0268 32`.
        expect(Array.from(alps.data)).toEqual([0x00, 0x03, 0x02, 0x68, 0x32]);
        expect(alps.data.length).toBe(5);
    });

    it("the legacy ALPS codepoint (17513) gets the same h2-only body", () => {
        const cfg: ClientHelloConfig = {
            ...alpsConfig(["h2", "http/1.1"]),
            extensionOrder: [
                ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                ExtensionType.APPLICATION_SETTINGS_OLD, // 17513
            ],
        };
        const hello = buildClientHello(cfg, fakeKeyPairs(["x25519"]), () => 0, crypto);
        const alps = parseExtensions(hello).find((e) => e.type === ExtensionType.APPLICATION_SETTINGS_OLD)!;
        expect(Array.from(alps.data)).toEqual([0x00, 0x03, 0x02, 0x68, 0x32]);
    });

    it("omits ALPS entirely when the ALPN list has no h2", () => {
        const hello = buildClientHello(alpsConfig(["http/1.1"]), fakeKeyPairs(["x25519"]), () => 0, crypto);
        const extensions = parseExtensions(hello);
        expect(extensions.find((e) => e.type === ExtensionType.APPLICATION_SETTINGS)).toBeUndefined();
        expect(extensions.find((e) => e.type === ExtensionType.APPLICATION_SETTINGS_OLD)).toBeUndefined();
        // ALPN itself is untouched by the ALPS filter.
        expect(extensions.find((e) => e.type === ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)).toBeDefined();
    });
});

describe("D8: initial ClientHello record carries legacy version 0x0301", () => {
    const PROFILE: ClientHelloConfig = {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: [0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        grease: true,
    };

    /** Transport that drives the sim on every HANDSHAKE write (HRR-aware). */
    class SimTransport extends FakeTransport {
        private readonly sim: TlsServerSim;
        constructor(sim: TlsServerSim) {
            super();
            this.sim = sim;
        }
        public override async write(data: Uint8Array): Promise<void> {
            await super.write(data);
            if (data.length > 0 && data[0] === ContentType.HANDSHAKE) {
                this.sim.onClientHello(data);
                for (const resp of this.sim.responses) {
                    this.readQueue.push(resp);
                }
            }
        }
    }

    it("writes `16 03 01` on the initial ClientHello record", async () => {
        const sim = new TlsServerSim();
        const transport = new SimTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
        const clientHelloRecord = transport.written[0]!;
        // Golden chrome-131 opens `16 03 01` — TLS 1.0 legacy version on the
        // initial ClientHello record (RFC 8446 §5.1 allows exactly this).
        expect(clientHelloRecord[0]).toBe(0x16);
        expect(((clientHelloRecord[1] ?? 0) << 8) | (clientHelloRecord[2] ?? 0)).toBe(CLIENT_HELLO_RECORD_VERSION);
        expect(CLIENT_HELLO_RECORD_VERSION).toBe(0x0301);
    });

    it("keeps ClientHello_2 (after HRR) on the 0x0303 default", async () => {
        const sim = new TlsServerSim({ helloRetryRequest: { selectedGroup: "x25519" } });
        const transport = new SimTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
        const handshakeWrites = transport.written.filter((w) => w[0] === ContentType.HANDSHAKE);
        expect(handshakeWrites.length).toBe(2);
        // Only the INITIAL ClientHello may carry 0x0301 (RFC 8446 §5.1); the
        // post-HRR resend is not an initial ClientHello and stays 0x0303.
        expect(handshakeWrites[0]![2]).toBe(0x01);
        expect(handshakeWrites[1]![1]).toBe(0x03);
        expect(handshakeWrites[1]![2]).toBe(0x03);
    });
});
