# Offline local preview record verifier

`python3 scripts/check-local-preview.py` checks saved records from the
[public fixture walkthrough](94-local-preview-walkthrough.md). It performs no
network request, server/agent/browser execution, Docker/cluster access, signing,
image build or publication. This is independent Dev/Demo tooling while broader
qualification and authority gates are temporarily deferred, not marked passed.

The only successful status is `consistent_saved_preview_records`, with scope
`offline_record_consistency_only`. This means the files agree with the supplied
pins and the supported fixture suite. Synthetic files can satisfy it. It cannot
authenticate capture, establish image/source build provenance, prove browser or
runtime behavior, physical storage durability, performance, PROFILE-LOAD, Alpha
or release acceptance. These remain explicit false flags in the output.

## Inputs and invocation

Supply pins from the independently reviewed artifact identity, not from the
same evidence files whose consistency is being checked:

```bash
python3 scripts/check-local-preview.py \
  --evidence target/OWNED_PREVIEW_CAPTURE \
  --source-commit REVIEWED_FULL_COMMIT \
  --image-reference REVIEWED_REPOSITORY@sha256:REVIEWED_DIGEST \
  --image-id sha256:REVIEWED_IMAGE_CONFIG_ID
```

The `image-reference` digest identifies the repository manifest; `image-id`
identifies the local image configuration. They are different identities. A
recorded `RepoDigests` association and matching pins do not prove the image was
built from the supplied commit. Use applicable release-trust/source/build evidence
for that claim. An unchanged commit string cannot describe an uncommitted build.

The evidence directory must contain these eleven named regular files:

| File | Required consistency |
| --- | --- |
| `project.txt` | A `signal-preview-` project identifier with 12 lowercase hex characters |
| `source-commit.txt` | Exact externally supplied full lowercase 40-hex source commit |
| `image-reference.txt` | Exact externally supplied digest-pinned reference |
| `image.txt` | Recorded `docker image inspect` configuration ID and JSON RepoDigests list matching the supplied pins |
| `inputs.sha256` | Exact five public inputs, no extra/duplicate/path-traversal entries; hashes match the current supported checkout files |
| `admission-http.txt` | 202 |
| `events-http.txt` | 200 |
| `findings-http.txt` | 200 |
| `admission.json` | Schema 1, four accepted, zero rejected, exact fixture IDs in order, no error |
| `events.json` | Schema 1, exactly four unique fixture IDs and complete canonical fixture payloads; query order may differ |
| `findings.json` | Schema 1, exactly two unique canonical non-nil finding UUIDs, the expected public rule metadata/time, singleton event references covering both matching events and empty fixture finding attributes |

Additional files (for example browser notes) are ignored; they are not treated as
qualifying evidence. Every supplied known input file is bounded to 128 KiB.
The five current public configuration/rule/fixture inputs are:

- `docker-compose.yml`
- `deploy/compose/server.yaml`
- `rules/examples/login-failure.yaml`
- `examples/local-preview/compose.yaml`
- `examples/local-preview/events.json`

The rule and fixture hashes are additionally pinned to this verifier's supported
suite, so editing a fixture and recomputing its recorded hash does not qualify
an unsupported suite. Fixture timestamps use the exact canonical strings;
equivalent alternate timestamp spellings are conservatively rejected. Arbitrary
customer events and other rules are not supported by this tool.

## Failure and evidence boundaries

The reader refuses oversized, symlink, hardlink and nonregular leaf files, uses
nonblocking opens so a FIFO cannot stall open, and checks pre/post file metadata.
JSON rejects duplicate keys and nonfinite values. Canonical event comparison
keeps boolean and numeric values distinct. Partial admission, missing/extra/
duplicate/mutated records, unexpected findings, wrong pins and incomplete hash
inventories fail with exit 1. CLI errors never echo server bodies, paths, tokens
or supplied pin values. A consistent record result exits 0.

Input and record hashes are emitted without record bodies. Treat hashes and
identity metadata according to the evidence-sharing policy. The helper never
reads environment credentials or writes a report file itself; callers may save
stdout inside a fresh owned capture directory. Do not overwrite historical
verification results to hide an incomplete attempt.

These file checks are bounded snapshot checks in a cooperative filesystem. They
do not anchor a workload's source/database directory through child retirement,
attest continuous file immutability, or impose a hard deadline on filesystem
operations. The tool has no authority to repair or dispose of resources. It does
not recompute the Rust finding-ID derivation or establish that a UUID originated
from the engine. All those claims require their own evidence.

Validation uses synthetic saved responses and owned temporary filesystem entries.
No successful fixture test is native pipeline evidence. Independent product or
release review is not supplied by a writer tooling review. The active 49,500 EPS
requirement, blocked workload gates and live-test/publication holds are unchanged.
