# Public local preview walkthrough

Status, 2026-11-01: **offline-prepared instructions; no current-source runtime or
browser pass**. Label any demonstration `0.1.0-dev.0 — demo-capable development
preview`. This fixture walkthrough does not qualify Alpha, PROFILE-LOAD, capacity,
security, production or a provider integration. It contains no customer data and
requires no private checkout. The older `examples/demo` stack remains separate.

## Operator prerequisites and evidence

Use a disposable local environment with an existing reviewed, locally loaded
server image referenced by digest. The image must map to an identified source
commit and reviewed build inputs; an image tag or operator-supplied commit string
alone does not establish that relationship. If no matching image exists, stop
and prepare/review the build separately. Do not silently substitute a historical
image, build the dirty checkout or pull an unreviewed image.

Reserve an unused Compose project name and loopback HTTP/metrics ports. If they
are occupied, stop; never terminate another process or reset another project.
Create a new evidence directory. Record preview label, source commit, image ID
and digest, configuration/rule/fixture hashes, architecture, host resources and
tool versions. Record whether the image and demonstration inputs share a commit;
any separately reviewed documentation/fixture inputs need explicit hashes.
Do not attach tokens, rendered secret-bearing configuration or real data.

The commands below are instructions for a separately authorized operator run.
They were not executed against Docker, a server or a browser during preparation.
They neither authorize nor rerun any process-ownership failure case.

## Setup

Run from the repository root in one Bash terminal after the prerequisites above.
Replace the identity placeholders with independently reviewed evidence, not the
current dirty HEAD or values copied back from the same capture being checked.

```bash
set -euo pipefail
export SIGNAL_PREVIEW_COMMIT='REVIEWED_SOURCE_COMMIT'
export SIGNAL_PREVIEW_IMAGE='REVIEWED_REPOSITORY@sha256:REVIEWED_MANIFEST_DIGEST'
export SIGNAL_PREVIEW_IMAGE_ID='sha256:REVIEWED_IMAGE_CONFIG_ID'
export SIGNAL_HTTP_PORT=18080
export SIGNAL_METRICS_PORT=19090
export SIGNAL_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
preview_project="signal-preview-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')"
preview_evidence="target/${preview_project}"
mkdir -m 700 "$preview_evidence"
preview_base="http://127.0.0.1:${SIGNAL_HTTP_PORT}"
printf '%s\n' "$preview_project" > "$preview_evidence/project.txt"
printf '%s\n' "$SIGNAL_PREVIEW_COMMIT" > "$preview_evidence/source-commit.txt"
printf '%s\n' "$SIGNAL_PREVIEW_IMAGE" > "$preview_evidence/image-reference.txt"
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' \
  "$SIGNAL_PREVIEW_IMAGE" > "$preview_evidence/image.txt"
sha256sum docker-compose.yml deploy/compose/server.yaml \
  rules/examples/*.yaml examples/local-preview/compose.yaml \
  examples/local-preview/events.json > "$preview_evidence/inputs.sha256"
preview_compose=(docker compose -p "$preview_project" \
  -f docker-compose.yml -f examples/local-preview/compose.yaml)
"${preview_compose[@]}" up -d --no-build --pull never signal
```

Require `/readyz` HTTP 200 within 60 seconds; after that, stop and retain the
failure instead of silently retrying startup. A bound startup probe:

```bash
preview_ready=false
for preview_attempt in {1..60}; do
  if curl --fail --silent --max-time 1 "$preview_base/readyz" >/dev/null; then
    preview_ready=true
    break
  fi
  sleep 1
done
test "$preview_ready" = true
```

This is a bound on attempts, not a hard 60-second wall-clock guarantee; record
actual elapsed time. If startup/probes fail, use only the owned project for
inspection and the cleanup step below. Do not proceed to inject fixtures.

## Send once, then verify persistence and findings

Send the four fixed public events **once into the empty project**. A failed or
ambiguous POST is not permission to resend: admission is at least once and
connection failure may hide a committed prefix. Retain it as incomplete.

```bash
preview_http=$(curl --silent --show-error --max-time 10 \
  --output "$preview_evidence/admission.json" --write-out '%{http_code}' \
  -H "Authorization: Bearer ${SIGNAL_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/local-preview/events.json \
  "$preview_base/v1/events/batch")
printf '%s\n' "$preview_http" > "$preview_evidence/admission-http.txt"
test "$preview_http" = 202
python3 - "$preview_evidence/admission.json" <<'PY'
import json, sys
response = json.load(open(sys.argv[1]))
expected = json.load(open('examples/local-preview/events.json'))['events']
assert response['accepted'] == 4 and response['rejected'] == 0
assert response['event_ids'] == [event['id'] for event in expected]
PY
```

A 202 confirms synced WAL admission only. Query the fixture source/time range and
example rule; allow at most 30 observations for asynchronous publication, then
stop as incomplete if counts/identities have not reconciled. Keep each observation and verifier result
in its own subdirectory, including incomplete observations. Never resend to make
a count pass. Each query has its own 5-second request timeout; record actual
elapsed time rather than treating this as a hard 30-second deadline.

```bash
preview_reconciled=false
for preview_attempt in {1..30}; do
  preview_observation="$preview_evidence/observation-${preview_attempt}"
  mkdir -m 700 "$preview_observation"
  for preview_record in project.txt source-commit.txt image-reference.txt image.txt \
    inputs.sha256 admission-http.txt admission.json; do
    cp -- "$preview_evidence/$preview_record" "$preview_observation/$preview_record"
  done
  curl --fail --silent --show-error --max-time 5 \
    -H "Authorization: Bearer ${SIGNAL_API_TOKEN}" \
    --output "$preview_observation/events.json" --write-out '%{http_code}' \
    "$preview_base/v1/events?source_name=local-preview-fixture&from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z&limit=10" \
    > "$preview_observation/events-http.txt"
  curl --fail --silent --show-error --max-time 5 \
    -H "Authorization: Bearer ${SIGNAL_API_TOKEN}" \
    --output "$preview_observation/findings.json" --write-out '%{http_code}' \
    "$preview_base/v1/findings?rule_id=auth.login-failure&limit=10" \
    > "$preview_observation/findings-http.txt"
  if python3 scripts/check-local-preview.py \
    --evidence "$preview_observation" \
    --source-commit "$SIGNAL_PREVIEW_COMMIT" \
    --image-reference "$SIGNAL_PREVIEW_IMAGE" \
    --image-id "$SIGNAL_PREVIEW_IMAGE_ID" \
    > "$preview_observation/offline-verification.json"
  then
    printf '%s\n' "$preview_observation" > "$preview_evidence/final-observation.txt"
    preview_reconciled=true
    break
  fi
  sleep 1
done
test "$preview_reconciled" = true
```

The [offline verifier](100-local-preview-evidence-verification.md) checks exact
fixture event payloads and finding references/metadata as well as the saved
identity/hash/status records. Consistent records do not prove capture authenticity,
image-to-source provenance, physical durability or that any request actually ran. The engineering cold-reconciliation/durability gates remain
separate. Unexpected errors, duplicates or missing IDs are incomplete/failed
observations, not waived limitations.

Open `http://127.0.0.1:18080/ui` (or the chosen HTTP port). Enter the token from
the running terminal without saving it in evidence. Find the two example login
findings and search the four fixture events; include the 2026-11-01 fixture date
if the UI defaults to recent events. Record browser observations separately:
API counts do not establish a browser pass. Capture sanitized feedback about
setup difficulty, finding clarity and event navigation, with the preview's
commit/image identity; no customer identifiers, secrets or production logs.

## Reset only this demo

```bash
"${preview_compose[@]}" down --volumes
unset SIGNAL_API_TOKEN
```

If the terminal ended after a failure, recover only this owned project name and
image reference from its `project.txt` and `image-reference.txt`, reconstruct the
same Compose command, and perform the reset. Do not guess an existing project.

This intentionally deletes the named data volume of the newly owned project.
Never use it on an existing/shared project or replace it with global prune,
container-name searches or broad filesystem deletion. Preserve sanitized
admission/query/browser/failure records and identity inputs. To demonstrate
again, create a new project/evidence directory and admit the fixtures once.
Do not assume in-memory token cleanup erases shell history or process memory;
never print or include it in a feedback bundle.

Compose options and project-volume semantics were checked through Context7
against [Docker Compose](https://github.com/docker/compose/blob/main/docs/reference/compose.md),
[up](https://github.com/docker/compose/blob/main/docs/reference/compose_up.md)
and [down](https://github.com/docker/compose/blob/main/docs/reference/compose_down.md).
This does not establish compatibility or a runtime pass for the operator's
installed version; record it and verify the rendered configuration privately.
