/**
 * Hostname validation against a parsed certificate (RFC 6125).
 *
 * The matching policy (SAN DNS names first, then legacy CommonName; wildcard
 * rules) is pure and independent of how a certificate is parsed or verified, so
 * it lives in its own module. `certificates.ts` re-exports these for the
 * historical import path.
 */

import type { Certificate } from "./certificates.js";

/**
 * Validate that a certificate is valid for the given hostname per RFC 6125.
 *
 * If the cert carries SAN DNS names, one must match (wildcard-aware, matching
 * a single left-most label and NOT crossing dots). Otherwise we fall back to
 * the legacy CommonName. IP-literal SANs are not matched here (server certs
 * virtually always use DNS names).
 */
export function validateHostname(cert: Certificate, hostname: string): boolean {
    const names = cert.subjectAltNames;
    if (names.length > 0) {
        return names.some((name) => matchDnsName(name, hostname));
    }
    if (cert.commonName !== undefined) {
        return matchDnsName(cert.commonName, hostname);
    }
    return false;
}

/** Match a DNS name (possibly wildcard) against a concrete hostname (RFC 6125 §6.4.3). */
export function matchDnsName(pattern: string, hostname: string): boolean {
    const p = pattern.trim().toLowerCase();
    const h = hostname.trim().toLowerCase();
    if (p.length === 0 || h.length === 0) {
        return false;
    }
    // Wildcard: only a leading "*." matches a single non-empty left label.
    if (p.startsWith("*.")) {
        const suffix = p.slice(1); // e.g. ".example.com"
        // The prefix before the suffix must be exactly one label (no dots).
        const prefix = h.slice(0, h.length - suffix.length);
        if (!h.endsWith(suffix)) {
            return false;
        }
        return prefix.length > 0 && !prefix.includes(".");
    }
    return p === h;
}
