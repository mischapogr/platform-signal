# Offline artifact inventory trust: local qualification

This bounded mechanism verifies a signed inventory with an externally pinned
Ed25519 public key. The current inventory purpose is `local-test`; verification
explicitly returns `production_release: false`. It neither installs updates nor
authorizes a release, registry publication or automatic rule/config reload.

`python3 scripts/release-trust.py --bundle <directory> --public-key <trusted-key>`
verifies the exact `inventory.json` bytes and 64-byte `inventory.sig` over the
domain `PLATFORM::SIGNAL/artifact-inventory/v1` followed by a zero byte and the
inventory. It then requires schema1, an explicit40-hex source revision and the
exact size/SHA256 of each declared artifact. Adjacent or embedded keys are never
implicit trust roots. A fingerprint in a report is an identity, not independent
proof that an operator approved that key.

Limits:262144inventory bytes,128unique artifacts,512MiB per artifact and1GiB
aggregate declared bytes. Duplicate JSON fields, unknown schema fields, boolean
numeric fields, traversal/noncanonical paths, symlinks and nonregular files are
rejected. Artifact hashing streams bounded chunks and rejects observed changes
while reading. The operation attests the bytes inspected; a caller must reverify
at use or consume an independently protected copy. It makes no claim of atomic
installation or authority against a privileged host operator.

`python3 scripts/check-release-trust.py --output target/<fresh-owned-path>`
qualifies actual OpenSSL Ed25519 signatures against current OSS lock/rule bytes
and an explicitly unattested local provenance fixture. It checks wrong trust
keys, tampered rule/inventory bytes, foreign domains, unsigned/forged signatures,
invalid schema/path/count/size fields, duplicates and symlinks. Private fixture
keys are generated only under the owned output and removed after the campaign.
Public keys, signed test inventory and bounded reports remain as evidence.

This is a RELEASE-TRUST mechanism slice. Current image SBOM generation, builder
provenance/attestation, selected baseline bundle qualification and real released
artifact trust remain separate gates. The unsigned dev0 candidate procedure is
unchanged. Runtime rule loading does not enforce this offline signature contract.
