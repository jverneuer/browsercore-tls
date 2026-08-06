/**
 * IANA TLS Protocol Version codes for the supported_versions extension.
 *
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
 */

export const VERSION_CODES: Readonly<Record<string, number>> = {
    "TLS 1.3": 0x0304,
    "TLS 1.2": 0x0303,
    "TLS 1.1": 0x0302,
    "TLS 1.0": 0x0301,
};
