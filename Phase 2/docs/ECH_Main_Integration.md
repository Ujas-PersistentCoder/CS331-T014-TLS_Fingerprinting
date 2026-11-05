# ECH integration with main — November 5, 2026

This integrates the local reduced checkpoint 3 experiment, remote ECH through
`8048488`, and main through `e3f9aba` (engine code through `fa6560e`). The checkpoint commits remain in history.

## Ownership and concurrency

The capture thread owns TLS record accumulation, TCP connection generations,
ECH observations, lifecycle maintenance, and JSON emission. These operations must
remain ordered even when processing the two directions of a connection.

Main's worker queues remain available through `-j`. After validating a complete
hello and retaining its observation, the producer copies the bounded record into
a job. Workers use their own parser scratchpads for fingerprint reporting,
catalog lookup, and optional JA4T/cross-layer diagnostics. SYN snapshots, the
current TTL, and initial/post-HRR role are copied into jobs. Workers never access
connection state or the JSON descriptor. Terminal output is synchronized.

Hello counters belong to the producer and are not incremented again by workers.
Consumers drain before `run()` returns, including capture errors and interruption.
Only the producer stops queue consumption after it has stopped producing jobs;
`stop()` requests capture interruption without prematurely ending consumers.
Direct TCP ingestion without `run()` retains synchronous behavior.

This preserves correctness by doing some hello parsing/hashing in both the
producer and workers. It does not establish performance parity with main.
The existing repeated-flow benchmark captures are not evidence of equivalent
work: ECH connection generations deliberately suppress delivered retransmissions.
A future optimization must preserve ordered observations and bounded ownership.

## Conflict decisions and compatibility

- Preserve main's JA4/JA4S specification fixes, optional JA4T/JA4TS, `-j`, `-c`,
  catalog synchronization, SYN correlation, and TCP offload handling.
- Preserve ECH's strict ServerHello extension framing, duplicate/version-length
  rejection, HRR exclusion, and conservative evidence boundaries.
- Keep the observed negotiated-version bytes in telemetry. Apply main's GREASE
  version fallback when computing JA4S, without inventing TLS 1.2 negotiation or
  supplying false ECH non-acceptance evidence.
- Preserve `--json`, quiet mode, exclusive output creation, and schema version 1.
  The charter's broader unified four-layer schema remains future integration;
  this PR does not add PQ inspection or passive acceptance classification.
- Build the declared GoogleTest v1.14.0 source statically. Debug also instruments
  that source with ASan/UBSan, matching its test consumers rather than mixing
  instrumented containers with a prebuilt test library.

## Validation

Validation passed 139 tests in each of Release (also built with `-Werror`) and
ASan/UBSan Debug, 15 lab checks, and 56 Python tests (run from `code/`). The lab
report regenerated successfully. Checks cover seven saved captures and four lab
captures, comparisons with
one/four workers and JA4T enabled; and main's JA4T lab with its extra catalog.
Two integration tests exercise worker draining/count invariance and the GREASE
version/fingerprint/evidence boundary.

The 63 original lab summaries remain historical outputs of the recorded engine.
Their replayed ECH metadata, client fingerprints, and experiment conclusions
remain unchanged. Server JA4S changes from the older `a56c5b993250` extension hash
to main's wire-order `234ea6891581` for the lab's `[43, 51]` extensions. Do not
rewrite the original evidence or claim exact full-summary parity after this fix.
The seven saved captures likewise change only server JA4S fingerprints.

No fresh live collection, Linux build, recognition-accuracy evaluation, or
performance-equivalence claim is established by these integration checks.
