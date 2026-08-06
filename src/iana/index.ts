/**
 * IANA TLS parameter registries — the single source of truth for wire codes.
 *
 * Each table maps canonical IANA names to their 2-byte wire values. These are
 * protocol-level constants, not browser profile data — they live here in
 * `@browsercore/tls` so every package that needs to validate or encode TLS
 * values imports from one canonical location.
 *
 * `@browsercore/profiles` and `@browsercore/fetch` both re-export or import
 * from this module rather than maintaining their own copies.
 */

export {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
} from "./cipher-suites.js";

export { NAMED_GROUP_CODES } from "./named-groups.js";

export { SIGNATURE_SCHEME_CODES } from "./signature-schemes.js";

export { VERSION_CODES } from "./versions.js";
