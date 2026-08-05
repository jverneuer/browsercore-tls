/**
 * X.509 certificate handling (RFC 8446 §4.4.2, RFC 5280).
 *
 * Parses DER-encoded certificates, validates hostnames against SAN/CN, and
 * verifies certificate chains against trust anchors. The cryptographic
 * signature verification itself is delegated to @browsercore/crypto — this module
 * owns validation policy and the top-level parse/verify orchestration only.
 *
 * The byte-level ASN.1 decoding lives in focused submodules so each layer can be
 * read and tested in isolation:
 *   - `der.ts`      — DER tag-length-value primitives (no X.509 semantics)
 *   - `cert-extensions.ts` — subject/issuer names, SAN, KeyUsage, BasicConstraints
 *   - `pem.ts`      — PEM container decoding (the only place that knows about
 *                     the BEGIN/END text wrapper; downstream code sees raw DER)
 */

import { crypto, type CryptoProvider } from "@browsercore/crypto";
import type { SignatureScheme } from "../types.js";
import { TlsHandshakeError, ensureTlsError } from "../errors.js";
import { constantTimeEqual } from "../utils.js";
import { validateHostname } from "./hostname.js";
import {
    oidToSignatureScheme,
    parseAlgorithmIdentifierOid,
    parseTime,
    peekTag,
    readTlv,
} from "./der.js";
import {
    parseBasicConstraints,
    parseCommonName,
    parseExtensionsBlock,
    parseKeyUsage,
    parseName,
    parseSubjectAltNames,
} from "./cert-extensions.js";
/** A parsed X.509 certificate (validation-relevant fields only). */
export interface Certificate {
    /** DER-encoded TBSCertificate bytes, needed for signature verification. */
    readonly tbsBytes: Uint8Array;
    /** DER-encoded SubjectPublicKeyInfo. */
    readonly subjectPublicKeyInfo: Uint8Array;
    /** Subject alternative DNS names (from the SAN extension), if any. */
    readonly subjectAltNames: readonly string[];
    /** Common Name from the subject DN, if present (legacy hostname match). */
    readonly commonName?: string;
    /** Not-before timestamp (epoch seconds). */
    readonly notBefore: number;
    /** Not-after timestamp (epoch seconds). */
    readonly notAfter: number;
    /** True if the certificate has the keyUsage bit for digital signature. */
    readonly keyUsageDigitalSignature: boolean;
    /** True if the certificate has the keyUsage bit for key encipherment/agreement. */
    readonly keyUsageKeyEncipherment: boolean;
    /** Signature algorithm used by the issuer over the TBSCertificate. */
    readonly signatureScheme: SignatureScheme;
    /** Raw signature value from the issuer. */
    readonly signatureValue: Uint8Array;
    /** DER-encoded SubjectPublicKeyInfo of the issuer (for chain building). */
    readonly issuer: string;
    /** True for a CA certificate. */
    readonly isCa: boolean;
}

/** An ordered certificate chain: leaf first, intermediates follow, root last. */
export interface CertificateChain {
    readonly leaf: Certificate;
    readonly intermediates: readonly Certificate[];
    readonly root: Certificate;
}

/** A trust anchor: a root certificate we trust a priori. */
export interface TrustAnchor {
    readonly subjectPublicKeyInfo: Uint8Array;
    readonly subject: string;
}

/**
 * Parse a single DER-encoded X.509 certificate.
 *
 * Decodes the outer Certificate SEQUENCE into its TBSCertificate, signature
 * algorithm, and signature value, then extracts the validation-relevant fields.
 * `tbsBytes` is captured as the EXACT DER span of the TBSCertificate so that
 * signature verification over it is byte-correct.
 *
 * Throws {@link TlsHandshakeError} with phase "certificate" on malformed input.
 */
export function parseCertificate(buf: Uint8Array): Certificate {
    // Outer Certificate SEQUENCE.
    const cert = readTlv(buf, 0);
    if (cert.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected Certificate SEQUENCE, got tag 0x${cert.tag.toString(16)}`),
        });
    }

    // First element: TBSCertificate. Capture its full DER span for verification.
    if (cert.valueStart >= cert.end) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("empty Certificate"),
        });
    }
    const tbs = readTlv(buf, cert.valueStart);
    if (tbs.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected TBSCertificate SEQUENCE, got tag 0x${tbs.tag.toString(16)}`),
        });
    }
    const tbsBytes = buf.subarray(tbs.start, tbs.end);

    // Walk the TBSCertificate fields in order.
    let o = tbs.valueStart;

    // version [0] EXPLICIT — optional, context-constructed tag 0xA0.
    if (peekTag(buf, o) === 0xa0) {
        o = readTlv(buf, o).end;
    }

    // serialNumber INTEGER — skip.
    o = readTlv(buf, o).end;

    // signature AlgorithmIdentifier.
    const signatureScheme = oidToSignatureScheme(parseAlgorithmIdentifierOid(buf, o));
    o = readTlv(buf, o).end;

    // issuer Name — skip past it but remember the span for the issuer string.
    const issuerTlv = readTlv(buf, o);
    const issuer = parseName(buf, issuerTlv.start, issuerTlv.end);
    o = issuerTlv.end;

    // validity SEQUENCE { notBefore, notAfter }.
    const validity = readTlv(buf, o);
    if (validity.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected validity SEQUENCE, got tag 0x${validity.tag.toString(16)}`),
        });
    }
    let v = validity.valueStart;
    const notBeforeTlv = readTlv(buf, v);
    const notBefore = parseTime(buf, notBeforeTlv.valueStart, notBeforeTlv.end, notBeforeTlv.tag);
    v = notBeforeTlv.end;
    const notAfterTlv = readTlv(buf, v);
    const notAfter = parseTime(buf, notAfterTlv.valueStart, notAfterTlv.end, notAfterTlv.tag);
    o = validity.end;

    // subject Name — skip (we only need CN for legacy hostname match).
    const subjectTlv = readTlv(buf, o);
    o = subjectTlv.end;

    // subjectPublicKeyInfo — capture the full DER span.
    const spkiTlv = readTlv(buf, o);
    if (spkiTlv.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected subjectPublicKeyInfo SEQUENCE, got tag 0x${spkiTlv.tag.toString(16)}`),
        });
    }
    const subjectPublicKeyInfo = buf.subarray(spkiTlv.start, spkiTlv.end);
    o = spkiTlv.end;

    // Optional trailing context tags: issuerUniqueID [1], subjectUniqueID [2],
    // extensions [3]. Only [3] carries fields we care about.
    let subjectAltNames: readonly string[] = [];
    let keyUsageDigitalSignature = false;
    let keyUsageKeyEncipherment = false;
    let isCa = false;
    let commonName: string | undefined;

    while (o < tbs.end) {
        const tag = peekTag(buf, o);
        if (tag === 0xa3) {
            // extensions [3] EXPLICIT: a SEQUENCE OF Extension inside a [3] wrapper.
            const extWrapper = readTlv(buf, o);
            const extensions = parseExtensionsBlock(buf, extWrapper.valueStart, extWrapper.end);
            for (const ext of extensions) {
                switch (ext.oid) {
                    case "2.5.29.17":
                        subjectAltNames = parseSubjectAltNames(ext.value);
                        break;
                    case "2.5.29.15":
                        ({ digitalSignature: keyUsageDigitalSignature, keyEncipherment: keyUsageKeyEncipherment } =
                            parseKeyUsage(ext.value));
                        break;
                    case "2.5.29.19":
                        isCa = parseBasicConstraints(ext.value);
                        break;
                    default:
                        break;
                }
            }
            o = extWrapper.end;
        } else if (tag === 0xa1 || tag === 0xa2) {
            // issuerUniqueID / subjectUniqueID — skip.
            o = readTlv(buf, o).end;
        } else {
            // Unknown trailing element — stop scanning.
            break;
        }
    }

    // Fall back to the subject's CN if no SAN DNS names were present.
    if (subjectAltNames.length === 0) {
        commonName = parseCommonName(buf, subjectTlv.start, subjectTlv.end);
    }

    // Outer signatureAlgorithm (skip) + signatureValue.
    // The TBS signature OID is authoritative for the scheme; the outer one
    // must match it but we don't re-derive the scheme from it here.
    const signatureAlgorithmEnd = readTlv(buf, tbs.end).end;
    const sigValueTlv = readTlv(buf, signatureAlgorithmEnd);
    if (sigValueTlv.tag !== 0x03) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected signatureValue BIT STRING, got tag 0x${sigValueTlv.tag.toString(16)}`),
        });
    }
    // signatureValue is a BIT STRING: first content byte is the "unused bits" count.
    const signatureValue = buf.subarray(sigValueTlv.valueStart + 1, sigValueTlv.end);

    // Under exactOptionalPropertyTypes, an optional `?:` property must be omitted
    // rather than set to undefined. Only attach `commonName` when we found one.
    if (commonName !== undefined) {
        return {
            tbsBytes,
            subjectPublicKeyInfo,
            subjectAltNames: Object.freeze(subjectAltNames),
            commonName,
            notBefore,
            notAfter,
            keyUsageDigitalSignature,
            keyUsageKeyEncipherment,
            signatureScheme,
            signatureValue,
            issuer,
            isCa,
        };
    }
    return {
        tbsBytes,
        subjectPublicKeyInfo,
        subjectAltNames: Object.freeze(subjectAltNames),
        notBefore,
        notAfter,
        keyUsageDigitalSignature,
        keyUsageKeyEncipherment,
        signatureScheme,
        signatureValue,
        issuer,
        isCa,
    };
}

/**
 * Validate that a certificate is valid for the given hostname per RFC 6125.
 * (Moved to {@link ./hostname.js} — re-exported here for the stable import path.)
 */
export { validateHostname, matchDnsName } from "./hostname.js";

/**
 * Verify a certificate chain: each cert is signed by the next, the root is in
 * the trust anchors, and the leaf is valid for the hostname and not expired.
 *
 * Signature verification is delegated to @browsercore/crypto. Throws
 * {@link TlsHandshakeError} with phase "certificate" on any failure.
 */
export function verifyChain(
    chain: CertificateChain,
    trustAnchors: readonly TrustAnchor[],
    hostname: string,
    now: number,
    provider: CryptoProvider = crypto,
): Promise<void> {
    // Not async: crypto.verifySignature returns a synchronous boolean (awaiting it
    // would be an error). Synchronous throws are caught and returned as a rejected
    // promise so callers can await uniformly; the original TlsHandshakeError is
    // propagated as-is (not re-wrapped) so its type reaches the caller.
    try {
        const certs = [chain.leaf, ...chain.intermediates, chain.root];

        // 1. Validity windows: every cert must currently be valid.
        for (const cert of certs) {
            if (now < cert.notBefore || now > cert.notAfter) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(
                        `certificate ${cert.issuer} not valid at ${now} (valid ${cert.notBefore}..${cert.notAfter})`,
                    ),
                });
            }
        }

        // 2. basicConstraints CA flags: every intermediate must be a CA. The root
        //    is authorized by the trust-anchor SPKI match (step 4), not by its own
        //    basicConstraints, so a self-signed trust anchor need not set cA.
        for (const cert of chain.intermediates) {
            if (!cert.isCa) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(`intermediate certificate ${cert.issuer} is missing basicConstraints cA`),
                });
            }
        }

        // 3. For each (subject, issuer) pair, verify the signature. The issuer's
        //    public key (SPKI) verifies the subject's signature over its TBSCertificate.
        const subjects = [chain.leaf, ...chain.intermediates];
        const issuers = [...chain.intermediates, chain.root];
        for (let i = 0; i < subjects.length; i++) {
            const subject = subjects[i];
            const issuer = issuers[i];
            if (subject === undefined || issuer === undefined) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(`certificate chain entry at index ${i} is missing`),
                });
            }
            const ok = provider.verifySignature(
                subject.signatureScheme,
                issuer.subjectPublicKeyInfo,
                subject.signatureValue,
                subject.tbsBytes,
            );
            if (!ok) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(
                        `signature verification failed: ${subject.issuer} not signed by ${issuer.issuer}`,
                    ),
                });
            }
        }

        // 4. The chain root's SPKI must match one of the trust anchors.
        const rootTrusted = trustAnchors.some((ta) =>
            constantTimeEqual(ta.subjectPublicKeyInfo, chain.root.subjectPublicKeyInfo),
        );
        if (!rootTrusted) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`root certificate ${chain.root.issuer} does not match any trust anchor`),
            });
        }

        // 5. Hostname validation against the leaf.
        if (!validateHostname(chain.leaf, hostname)) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`hostname "${hostname}" does not match leaf certificate`),
            });
        }
        return Promise.resolve();
    } catch (cause) {
        // Every throw in the body is a TlsHandshakeError (an Error); keep the
        // original rejection so its type reaches the caller. Only fall back to a
        // generic TlsError if a non-Error somehow escapes.
        if (cause instanceof Error) {
            return Promise.reject(cause);
        }
        return Promise.reject(ensureTlsError(cause));
    }
}

export { pemToDer } from "./pem.js";
