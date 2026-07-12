# VerifiedPluginLoad

`VerifiedPluginLoad` is the Android library that decides whether an installed plugin APK may supply native code to Fold Craft Launcher, Zalith Launcher, Pojav Glow·Worm and other launchers. It does not load plugins itself.

## Publishing a trust-list update

The list payload is signed as its exact UTF-8 byte sequence with the Ed25519 key whose public half is compiled as `VPL_TRUST_LIST_ROOT_PUBLIC_KEY`. Publish the unchanged JSON bytes and a detached 64-byte Ed25519 signature, either as raw bytes or base64 text, at the two HTTPS URLs passed in `VerifiedPluginLoadConfig`.

The root private key is a release-management secret. It must not be committed to this repository, bundled in an APK, or placed in launcher settings. Rotate it only by shipping a new launcher build containing the new public key.

VPL rejects unsigned content, schema violations, duplicate IDs or hashes, and list-version rollback. It stages both files, validates the staged pair again, then atomically replaces the active files while retaining the prior valid pair.

Every prefix must serve the same pair of files. VPL downloads pairs from all configured mirrors in parallel, uses the first pair that completes and passes signature, schema, and rollback checks, then cancels the remaining requests. If the configuration is incomplete, the app deliberately stays on its signed local or built-in list rather than attempting an unauthenticated update.

## Trust decisions

VPL evaluates every current APK signing certificate with these non-configurable rules:

- A globally `banned` certificate always returns `BANNED`, including when the user previously trusted the key or its author.
- A trusted author accepts that author's current `active` certificates.
- An explicit user key trust accepts that exact certificate. It remains effective if a later signed list associates the same key with an author.
- An `active` listed key without either trust record returns `PENDING_TRUST`; an unknown signed key returns `UNTRUSTED`.
- Missing, unreadable, unsigned, or unparseable APK signatures return `VERIFICATION_FAILED` and must never enter a trust-confirmation path.

Trust-list `confidence` is fixed as follows: `0` means registered but not trustable for author-level approval, `1` means basic confidence with a confirmation warning, and `2` means high confidence with the normal author confirmation. These values never weaken a global key ban.

The parser accepts only `format_version: 1`, canonical lowercase UUIDs, canonical complete `sha256:<64 uppercase hex>|sha1:<40 uppercase hex>` fingerprints, unique author UUIDs and certificate hashes, HTTPS author links, and strictly bounded field sizes. Unknown and duplicate JSON fields are rejected.
