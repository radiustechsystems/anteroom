/* Anteroom adapter for the vendored js-sha256 browser build.
 *
 * The upstream implementation is js-sha256 1.0.0 by Chen, Yi-Cyuan, licensed
 * under MIT. Its unmodified minified browser build is served immediately before
 * this file. See THIRD_PARTY_NOTICES.md for the source and complete notice.
 */
"use strict";

/* anteroomSHA256 hashes a Uint8Array and returns a 32-byte Uint8Array. */
function anteroomSHA256(input) {
  if (typeof sha256 !== "function" || typeof sha256.array !== "function") {
    throw new Error("js-sha256 fallback did not load");
  }
  return new Uint8Array(sha256.array(input));
}
