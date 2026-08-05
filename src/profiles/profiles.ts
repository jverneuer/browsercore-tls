/**
 * ClientHello configuration profiles (placeholder).
 *
 * This module defines the local `TlsProfile` shape and a couple of example
 * configurations. Once @browsercore/profiles is built, it becomes the single source
 * of truth and this module will re-export from there. Keeping the shape here
 * avoids a circular dependency while @browsercore/profiles is not yet ready.
 */

import type { ClientHelloConfig } from "../types.js";
import { TlsProfileError } from "../errors.js";

/**
 * A TLS profile: a named, reusable ClientHello configuration.
 * Higher layers (HTTP/2, fetch) select a profile by name.
 */
export interface TlsProfile {
    readonly name: string;
    readonly config: ClientHelloConfig;
}

/**
 * TLS 1.3 only, modern ciphers, X25519 + secp256r1 key shares.
 *
 * Extension order mirrors chrome-140's GREASE-inclusive layout so this
 * placeholder profile exercises the full order-driven extension path.
 */
export const MODERN_TLS13_PROFILE: TlsProfile = {
    name: "modern-tls13",
    config: {
        cipherSuites: [
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        extensionOrder: [
            0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
        ],
        keyShareGroups: ["x25519", "secp256r1"],
        signatureAlgorithms: [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
        ],
        supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 }],
        serverName: "",
        grease: true,
    },
};

/**
 * Broad TLS 1.3 profile: the same modern ciphers as {@link MODERN_TLS13_PROFILE}
 * plus secp384r1 key shares and additional signature algorithms, for servers
 * that require a broader offer. TLS 1.2 suites are advertised for fallback; the
 * handshake driver branches to runTls12Handshake() if the server selects one.
 */
export const COMPATIBILITY_PROFILE: TlsProfile = {
    name: "compatibility",
    config: {
        cipherSuites: [
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        // Firefox-128 style order: no GREASE, no session_ticket/renegotiation_info.
        extensionOrder: [0, 10, 11, 13, 16, 18, 23, 35, 41, 43, 45, 51, 65281],
        keyShareGroups: ["x25519", "secp256r1", "secp384r1"],
        signatureAlgorithms: [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
        ],
        supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 }],
        serverName: "",
        grease: false,
    },
};

/** Registry of profiles by name. */
export const PROFILES: Readonly<Record<string, TlsProfile>> = {
    [MODERN_TLS13_PROFILE.name]: MODERN_TLS13_PROFILE,
    [COMPATIBILITY_PROFILE.name]: COMPATIBILITY_PROFILE,
};

/** Look up a profile by name, or undefined if unknown. */
export function getProfile(name: string): TlsProfile | undefined {
    return PROFILES[name];
}

/** Resolve a profile and fill in the serverName (which is connection-specific). */
export function resolveProfile(name: string, serverName: string): ClientHelloConfig {
    const profile = PROFILES[name];
    if (!profile) {
        throw new TlsProfileError(name);
    }
    return { ...profile.config, serverName };
}

