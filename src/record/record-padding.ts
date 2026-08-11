/**
 * ClientHello record padding (RFC 7685 / RFC 8446 §4.1.2).
 *
 * Real browsers pad the ClientHello to a fixed length (512 bytes for Chrome) so
 * that the fingerprint does not leak the exact number of extensions or cipher
 * suites offered. The padding is applied via the PADDING extension (type 21),
 * whose body is a run of zero bytes.
 *
 * This module owns the padding *computation*: given the current ClientHello
 * message size and the target length, it returns how many zero bytes the
 * PADDING extension body must contain. The actual byte emission happens in the
 * ClientHello builder.
 */

import type { ClientHelloConfig } from "../types.js";
import { ExtensionType } from "../extensions/extensions.js";

/**
 * Compute the number of zero bytes needed in the PADDING extension body to
 * reach the target ClientHello message length.
 *
 * The function accounts for whether the PADDING extension is already in the
 * profile's `extensionOrder`. If it is, the probe message size already includes
 * the 4-byte PADDING extension header (type + length) with a 0-byte body, so
 * the body just needs `targetSize - probeSize` bytes. If it is not, the
 * PADDING extension will be appended, adding a 4-byte header that must be
 * subtracted from the available body budget.
 *
 * @param probeMessageSize The total ClientHello message size with a 0-byte
 *        PADDING extension body (or no PADDING extension if it's absent from
 *        the extension order).
 * @param config           The ClientHello configuration carrying
 *        `recordPadding` and `extensionOrder`.
 * @returns Number of zero bytes for the PADING body; 0 when no padding is
 *          needed (target not set, already at/above target, or negative body).
 */
export function computePaddingExtensionBody(
    probeMessageSize: number,
    config: ClientHelloConfig,
): number {
    if (config.recordPadding === undefined) {
        return 0;
    }
    if (probeMessageSize >= config.recordPadding) {
        return 0;
    }

    const paddingInOrder = config.extensionOrder.includes(ExtensionType.PADDING);
    if (paddingInOrder) {
        // The probe already counts the 4-byte extension header + 0-byte body.
        // Every additional body byte increases the total by exactly one.
        return config.recordPadding - probeMessageSize;
    }

    // The PADDING extension will be appended: its 4-byte header (type + length)
    // is NOT in the probe, so reserve space for it.
    const bodySize = config.recordPadding - probeMessageSize - 4;
    return Math.max(bodySize, 0);
}
