# LESSONS - auto-maintained by scripts/lessons.py

> Machine-owned. Do NOT hand-edit. Changes are overwritten on the next `lessons.py` write.
> Canonical state lives in `.specs/lessons.json`. Edit lessons only via the script.
> promote_threshold=2 distinct features · window_days=45 · quarantine_threshold=2

## Confirmed (load these at Specify/Design)

Corroborated across multiple features. Safe to apply as guidance.

_none_

## Candidates (under observation - do NOT load as guidance yet)

Seen once or not yet corroborated. Tracked, not trusted.

### L-001 - When an AC requires correlating a live handshake/capture artifact end-to-end but the dev environment lacks the privilege or verified offsets to run it, add the deferred E2E test as an explicit follow-up task in tasks.md rather than leaving the AC covered only at the unit/format level.
- signal: `spec_precision_gap` · recurrence: 1 feature(s) · scope: `internal/keylog` · harmful: 0
- features: 02-uprobe-keylog
- evidence: validation.md#Spec-Anchored Acceptance Criteria (TLS 1.3/1.2 E2E client_random correlation) (internal/keylog)
- last seen: 2026-09-10T06:10:15Z

### L-002 - When a spec AC says the system SHALL log a specific field, grep for an actual logger call emitting that field before marking the task done — a passing artifact-growth or status-code test does not prove the log line was ever written.
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `logging` · harmful: 0
- features: 03-capture-harness
- evidence: spec.md P2 'End-to-end real-cert smoke test' AC2; internal/proxy/relay.go:69-83 (logging)
- last seen: 2026-09-12T23:17:35Z

### L-003 - A test named after a comparison (parity, identical, equivalent) must actually assert equality of the compared outputs — starting and stopping two code paths without diffing their results is not evidence of parity.
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `testing` · harmful: 0
- features: 03-capture-harness
- evidence: internal/capture/tcpdump_it_test.go:19-47 TestBackendParity_TcpdumpAndGopacketDecryptIdentically (testing)
- last seen: 2026-09-12T23:17:35Z

### L-004 - When a spec AC is a deployment/process-startup ordering guarantee, verify it against the actual orchestration script (e.g. pod-up.sh container launch order), not just the application-level code — orchestration commits can drift out of sync with the ordering guarantee they're supposed to implement.
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `deploy` · harmful: 0
- features: 02-uprobe-keylog
- evidence: KEYLOG-05 (deploy)
- last seen: 2026-09-13T02:26:55Z

### L-005 - An AC phrased as 'leaves existing behavior X unmodified' needs either an explicit code-inspection citation (what APIs were NOT called) or a test that would fail if X were touched — a passing happy-path test alone does not prove X was left alone.
- signal: `spec_precision_gap` · recurrence: 1 feature(s) · scope: `internal/keylog` · harmful: 0
- features: 02-uprobe-keylog
- evidence: KEYLOG-03 (internal/keylog)
- last seen: 2026-09-13T02:26:59Z

### L-006 - When a Done-when criterion implements a failure-handling path (retry/backoff/silent-drop), add a test that actually forces that failure path (e.g. point at an unreachable endpoint) rather than only exercising the happy path.
- signal: `spec_precision_gap` · recurrence: 1 feature(s) · scope: `preload` · harmful: 0
- features: 02-uprobe-keylog
- evidence: KEYLOG-08 (preload)
- last seen: 2026-09-13T02:27:04Z

### L-007 - When a task's Done-when criterion pins an existing file as 'must stay unchanged', satisfy shared-type dependencies by extracting the minimal needed piece into a new sibling file rather than editing the frozen file, and mark the extraction with a SPEC_DEVIATION comment so verifiers can trace why the new file exists.
- signal: `spec_deviation` · recurrence: 1 feature(s) · scope: `internal/keylog` · harmful: 0
- features: 02-uprobe-keylog
- evidence: internal/keylog/label.go:1 (internal/keylog)
- last seen: 2026-09-13T02:27:08Z

### L-008 - When an architecture decision (AD-xxx) supersedes a spec.md acceptance criterion, amend that spec.md's AC text and Assumptions table with a revision note in the same commit, not only a prose addendum in tasks.md — otherwise spec.md silently diverges from the implementation it is supposed to be the source of truth for.
- signal: `spec_precision_gap` · recurrence: 1 feature(s) · scope: `spec-authoring` · harmful: 0
- features: 03-capture-harness
- evidence: validation.md#Phase 4 addendum re-verification (AD-010) (spec.md CAPTURE-09 AC1/AC2) (spec-authoring)
- last seen: 2026-09-13T02:48:28Z

### L-009 - When a task's 'What' description names a specific new assertion (e.g. a namespace/capability-absence check), add it to that task's 'Done when' checklist too — otherwise the assertion can be silently dropped during implementation without failing the task's own completion criteria.
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `task-authoring` · harmful: 0
- features: 03-capture-harness
- evidence: validation.md#Phase 4 addendum re-verification (AD-010) (deploy/podman/pod_e2e_test.go Ranked gap 2) (task-authoring)
- last seen: 2026-09-13T02:48:28Z

### L-010 - Run the privileged/e2e test ladder for real (sudo + real pod) before claiming an AC verified; tests that always skip on missing root/tools hid four shipped capture bugs (zero-byte pcapng, ifindex mismatch, GSO truncation, --retain never forwarded).
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `testing,e2e,privileged` · harmful: 0
- features: 03-capture-harness
- evidence: .specs/STATE.md AD-011/AD-012 (testing,e2e,privileged)
- last seen: 2026-09-19T17:34:55Z

### L-011 - Run the privileged/e2e test ladder for real (sudo + real pod) before claiming an AC verified; tests that always skip on missing root/tools leave core behaviour with zero executing assertions.
- signal: `ac_gap` · recurrence: 1 feature(s) · scope: `testing,e2e,privileged` · harmful: 0
- features: 01-ebpf-redirect
- evidence: bpf/connect4_it_test.go:109 (testing,e2e,privileged)
- last seen: 2026-09-19T17:34:55Z

## Quarantined (failed when applied - ignore)

A confirmed lesson that recurred alongside failure. Kept for the maintainer to review.

_none_
