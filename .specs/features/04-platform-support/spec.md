# Platform Support Specification

**Feature dir**: `.specs/features/04-platform-support/`
**Milestone**: M4 — Platform support
**Source**: [AD-013](../../STATE.md), [TDD — Supported platforms](../../../docs/technical-design-document.md), [PRD](../../../docs/prd/product-requirements-document.md)

## Problem Statement

Almost every claim this project makes about where it runs is unverified: all development and
testing has happened on a single developer workstation (Ubuntu 24.04.5, kernel
`7.0.0-31-generic`), which is not a supported-platform claim. One piece of real but partial
evidence does exist — the `deploy/podman` e2e suite has been executed for real on that
workstation (2026-09-18: 4 passed / 1 skipped / 0 failed, the skip being the disclosed CAPTURE-04
limitation, AD-012) — so the residual work is "clean VM + 24.04 GA kernel + zero skips", not
"never run". AD-013 names six target distributions for Kubernetes worker nodes, but the
`deploy/podman` harness hard-codes host-specific assumptions: it disables **both** AppArmor and
seccomp confinement on the sidecar (AD-009, `deploy/podman/pod-up.sh:123-124` — each profile
independently blocks a step of BPF map create/pin), prepares bpffs, and resolves a
podman-specific pod cgroup path. Of those two confinement flags only the AppArmor half is
distro/LSM-specific and therefore Tier-1 profile data; podman's default seccomp profile is a
container-runtime default that is the same on every distribution. Porting to another distribution
today means rewriting the script rather than describing a new platform. This feature verifies
Tier 1 for real and introduces the seam that makes the remaining tiers additive.

## Goals

- [ ] `go test -race -tags='integration e2e' ./deploy/podman/...` passes on a clean Ubuntu 24.04 LTS VM with zero failures and zero skips, making Tier 1 the first genuinely `Verified` platform.
- [ ] Host-specific behaviour is isolated behind a named platform profile, so adding a distribution is a profile addition rather than a harness rewrite.
- [ ] An operator can determine whether an arbitrary node is usable before deploying, via a single preflight command that names any missing prerequisite and distinguishes the sidecar's runtime prerequisites from the harness's verification-time ones.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
| ------- | ------ |
| Verifying Tiers 2–6 (Bottlerocket, Flatcar, Talos, Fedora CoreOS, Rocky) | Scoped out per the operator's Tier-1-plus-seam decision; each needs its own real e2e run and becomes its own feature once the seam exists |
| A concrete SELinux policy module | Cannot be designed honestly without a SELinux platform to test against; the seam only has to make confinement *pluggable*, not solve tier 2/3/5/6 confinement |
| Kubernetes manifests, operators, or a CNI/DaemonSet deployment path | AD-013 defines target *node OSes*; production Kubernetes remains an explicit PRD non-goal |
| Rootless Podman | The redirect program types require rootful (AD-007); unchanged by this feature |
| Closing CAPTURE-04 (the capture-backend work in Feature 03 Phase 6) | Belongs to Feature 03 and is a **prerequisite** to this feature, not part of it |
| Relaxing or overriding a host's own `tcpdump`/LSM confinement | A host security policy this project neither controls nor should weaken; the parity test skips honestly instead |
| Multi-node / cluster-level validation | Single-node verification is the unit of platform support here |

---

## Assumptions & Open Questions

Every ambiguity is resolved or recorded here — nothing is left silently unclear.

| Assumption / decision | Chosen default | Rationale | Confirmed? |
| --------------------- | -------------- | --------- | ---------- |
| Execution order vs CAPTURE-04 | Feature 03 Phase 6 lands **before** this feature executes; this spec depends on that phase's *outcome* (a `./deploy/podman/...` run with no CAPTURE-04 skip), not on its contents, which are still being revised | Platform validation runs the e2e suite; rewriting the capture backend afterwards would invalidate and force a re-run of every platform's evidence | y |
| Feature scope | Tier 1 (Ubuntu 24.04 LTS) verified + the portability seam; Tiers 2–6 deferred | Smallest closeable unit that yields a real reference platform; avoids a sprawling six-platform task list that never closes | y |
| Which test suite gates a platform's status | Only `./deploy/podman/...` (tags `integration e2e`) gates `Verified`; skips elsewhere are recorded and named but non-blocking | It is the only suite that exercises a whole real pod on the candidate host; letting any package's environment-gated skip block the status makes every platform permanently unverifiable | y |
| Out-of-suite skips vs `Verified` | A skip outside that suite is named in the platform's evidence record but does not by itself withhold `Verified` | Stock Ubuntu 24.04's own `tcpdump` package installs `/etc/apparmor.d/usr.bin.tcpdump`, which denies the signal `internal/capture`'s backend-parity test needs; treating that skip as blocking would make the reference platform unverifiable by construction | y |
| Runtime vs verification-time prerequisites | Two documented sets: *runtime* (kernel version, BTF, cgroup v2 unified hierarchy, `cgroup_sock_addr`/`sockops`) and *verification-time* (rootful podman, `tshark`, `tcpdump`, outbound TLS egress to the smoke endpoint); the probe checks the second set only when asked for it | The zero-skip bar is unreachable otherwise — the suite skips on missing root, `tshark` or egress, none of which a node needs to *run* the sidecar; merging the lists would also fail nodes that are perfectly able to run it | y |
| Unmatched-host escape hatch | An explicit `PLATFORM_PROFILE` env var selects a profile by name and is logged as an unverified-platform override; without it an unmatched host fails fast | Strict detection alone locks out the only machine the suite has ever run on (Ubuntu 24.04.5, kernel `7.0.0-31-generic` — neither 24.04 GA nor HWE) and every future kernel variant; an override that announces itself keeps the evidence honest without blocking work | y |
| VM provisioning mechanism | A documented, scripted path using `cloud-init` plus a `deploy/vm/` script — no new build tooling (no Vagrant/Packer dependency) | Works against any hypervisor or cloud image, keeps the dependency surface at what the project already requires, and stays reproducible for CI later | n |
| Which Ubuntu 24.04 kernel | The 24.04 GA kernel is the baseline that must pass; HWE is tested opportunistically and recorded separately | GA is what a default 24.04 node ships; claiming support on HWE only would overstate coverage | n |
| Confinement on non-AppArmor tiers | The seam exposes confinement as profile data; the actual SELinux decision is deferred to the per-tier feature | Designing a policy without a SELinux host to test it on would produce an unverifiable guess — exactly the overclaim pattern this project has been cleaning up | n |
| Definition of "clean VM" | A stock cloud/server image with only the documented prerequisites installed, never a developer workstation | The whole point is to stop inferring platform support from one hand-tuned machine | y |
| Preflight probe form | A shell script under `deploy/` (not a Go subcommand) | It must run on a candidate node *before* any binary is built or shipped there | n |

**Open questions:** none — all resolved or logged above.

---

## User Stories

### P1: Verified Tier-1 reference platform ⭐ MVP

**User Story**: As an operator evaluating this project, I want Ubuntu 24.04 LTS proven end-to-end on a clean machine so that I can trust the supported-platform claim instead of a developer's workstation result.

**Why P1**: Without one genuinely verified platform, every statement in the TDD matrix is aspiration. This is the feature's reason to exist.

**Acceptance Criteria**:

1. WHEN `go test -race -tags='integration e2e' ./deploy/podman/...` is run on a clean Ubuntu 24.04 LTS VM that satisfies every documented verification-time prerequisite THEN the system SHALL report zero failed tests and zero skipped tests.
2. WHEN the harness is brought up on that VM THEN the system SHALL require no edits to `deploy/podman/pod-up.sh` beyond documented environment variables.
3. IF a documented verification-time prerequisite is absent on that VM THEN the system SHALL name the missing prerequisite and SHALL NOT record that run as Tier-1 evidence, so that a zero-skip result can never come from a suite that never ran.

**Independent Test**: Provision a stock Ubuntu 24.04 VM, run the documented prerequisite step, run the preflight probe in both modes (both exit zero), then run `sudo go test -race -tags='integration e2e' ./deploy/podman/...` and observe 0 failed / 0 skipped; separately remove `tshark` and confirm the run is refused with `tshark` named rather than reported as a clean pass.

---

### P1: Platform profile seam ⭐ MVP

**User Story**: As a maintainer adding a new distribution, I want every host-specific behaviour expressed as profile data so that supporting a distro does not mean rewriting the harness.

**Why P1**: This is what makes Tiers 2–6 additive. Without it, each new distro forks `pod-up.sh` and the six-platform commitment in AD-013 becomes unmaintainable.

**Acceptance Criteria**:

1. The system SHALL resolve LSM confinement flags, bpffs preparation, and pod cgroup-path resolution through a single named platform profile rather than inline host-specific commands.
2. WHEN a platform profile is selected THEN the system SHALL apply only that profile's confinement settings, leaving the other profiles' settings unused.
3. IF no platform profile matches the detected host and no `PLATFORM_PROFILE` override is set THEN the system SHALL exit non-zero with a message naming the unsupported host and the available profile names, rather than silently applying Tier 1's AppArmor settings.
4. WHEN `PLATFORM_PROFILE` names an existing profile at bring-up THEN the system SHALL use that profile instead of host detection and SHALL log an unverified-platform override naming both the chosen profile and the detected host.
5. The system SHALL express AD-009's `--security-opt apparmor=unconfined` as Tier-1 profile data because it is distro/LSM-specific, and SHALL apply `--security-opt seccomp=unconfined` from the shared bring-up path rather than from any profile because podman's default seccomp profile is not distro-specific.

**Independent Test**: Add a stub profile for a non-AppArmor platform and confirm the harness selects it, omits `apparmor=unconfined`, still passes `seccomp=unconfined`, and requires no edit to the shared bring-up logic; then run with `PLATFORM_PROFILE` set to that stub on this Ubuntu host and confirm the override is honoured and logged as unverified.

---

### P1: Preflight capability probe ⭐ MVP

**User Story**: As an operator, I want a single command that tells me whether a candidate node can run this sidecar so that I find out before deploying rather than from a confusing runtime failure.

**Why P1**: The project has four hard kernel/runtime prerequisites that fail in unrelated-looking ways, and the verification suite has four more of its own. AD-013 explicitly lists probes; this makes them executable.

**Acceptance Criteria**:

1. WHEN the preflight probe runs on a node THEN the system SHALL check kernel version, BTF availability, cgroup v2 unified hierarchy, and `cgroup_sock_addr`/`sockops` program-type support, reporting them as the sidecar's runtime prerequisites.
2. IF any checked prerequisite is missing THEN the system SHALL exit non-zero and name the specific failing prerequisite.
3. WHEN the probe finishes with every checked prerequisite satisfied THEN the system SHALL exit zero and SHALL report no failing prerequisite.
4. The system SHALL run the probe without requiring the sidecar binary or its container images to be present on the node.
5. WHEN the probe is invoked in its verification-time mode THEN the system SHALL additionally check rootful podman, `tshark`, `tcpdump`, and outbound TLS egress to the smoke test's endpoint, and SHALL label these as verification-time prerequisites distinct from the runtime prerequisites of criterion 1.

**Independent Test**: Run the probe on the Tier-1 VM in both modes (expect exit 0 from each) and on a deliberately non-conforming host or with a check forced to fail (expect non-zero plus the prerequisite's name); confirm the default mode still exits zero on a node that has no `tshark`, proving the two prerequisite sets are genuinely separate.

---

### P2: Reproducible VM provisioning

**User Story**: As a maintainer, I want the Tier-1 VM built from a scripted definition so that the verification result is reproducible rather than a one-off manual setup.

**Why P2**: The evidence is only trustworthy if someone else can rebuild the machine. Not MVP because a documented manual path still yields a valid first verification.

**Acceptance Criteria**:

1. WHEN the provisioning script is run against a stock Ubuntu 24.04 image THEN the system SHALL produce a VM with every documented runtime and verification-time prerequisite installed.
2. WHEN the provisioning script is run twice against the same target THEN the system SHALL converge to the same state without error.
3. IF a required package or image cannot be fetched THEN the system SHALL exit non-zero and name the unavailable dependency.

**Independent Test**: Run provisioning twice against a fresh image; confirm the second run succeeds and the preflight probe exits zero in both modes after each run.

---

### P2: Honest platform status tracking

**User Story**: As a reader of the docs, I want a platform's status to reflect actual evidence so that the support matrix never overstates what has been tested.

**Why P2**: This project has already had to remove overclaims from its own design docs; the matrix should not become the next one.

**Acceptance Criteria**:

1. WHILE a platform has no recorded `./deploy/podman/...` evidence the system SHALL show that platform's status as `Planned` in the TDD supported-platform matrix.
2. WHEN a platform's status is recorded as `Verified` THEN the system SHALL cite the run that justifies it, naming the suite, the date, and the passed/skipped/failed counts.
3. The system SHALL replace that platform's expected kernel value in the TDD matrix with the kernel version measured during the cited run.
4. WHEN a platform is recorded as `Verified` THEN the system SHALL list, in that platform's evidence record, every test skipped outside `./deploy/podman/...` together with the host-side cause of each skip.

**Independent Test**: Inspect the TDD matrix after Tier-1 verification: Ubuntu's row reads `Verified` with a cited run and a measured kernel, its evidence record names each out-of-suite skip and its cause, and all other rows still read `Planned`.

---

## Edge Cases

- IF the host runs a kernel that lacks `BPF_PROG_TEST_RUN` for `CGroupSockAddr` THEN the system SHALL still pass platform verification, because per-platform coverage comes from the e2e suite rather than that test.
- IF the reference platform's packaged `tcpdump` is confined such that it cannot be signalled (stock Ubuntu 24.04 installs `/etc/apparmor.d/usr.bin.tcpdump`, which denies signal delivery) THEN the system SHALL record and name that skip of `internal/capture`'s backend-parity integration test in the platform's evidence record, and SHALL still allow the platform to reach `Verified`, because that test is outside PLATFORM-01's `./deploy/podman/...` suite and the confinement is shipped by the reference platform itself.
- IF the host uses a cgroup manager whose pod cgroup path differs from Tier 1's THEN the system SHALL resolve the path through the platform profile rather than assuming Tier 1's layout.
- IF the node has cgroup v1 or a hybrid hierarchy THEN the preflight probe SHALL fail and name the unified-hierarchy requirement.
- IF `PLATFORM_PROFILE` names a profile that does not exist THEN the system SHALL exit non-zero listing the available profile names, rather than falling back to host detection.
- WHEN the sidecar image's libc differs from the build's link mode THEN the system SHALL fail fast with the static-linking requirement named, rather than an opaque exec error.

---

## Requirement Traceability

One requirement ID per acceptance criterion.

| Requirement ID | Story | Acceptance criterion | Phase | Status |
| -------------- | ----- | -------------------- | ----- | ------ |
| PLATFORM-01 | P1: Verified Tier-1 reference platform | AC1 — `./deploy/podman/...` reports 0 failed / 0 skipped on a clean 24.04 VM | - | Pending |
| PLATFORM-02 | P1: Verified Tier-1 reference platform | AC2 — no `pod-up.sh` edits beyond documented env vars | - | Pending |
| PLATFORM-03 | P1: Verified Tier-1 reference platform | AC3 — absent verification-time prerequisite named; run not counted as evidence | - | Pending |
| PLATFORM-04 | P1: Platform profile seam | AC1 — confinement, bpffs prep, and cgroup path resolved via one named profile | - | Pending |
| PLATFORM-05 | P1: Platform profile seam | AC2 — only the selected profile's confinement settings applied | - | Pending |
| PLATFORM-06 | P1: Platform profile seam | AC3 — unmatched host with no override fails fast, naming host and profiles | - | Pending |
| PLATFORM-07 | P1: Platform profile seam | AC4 — `PLATFORM_PROFILE` override honoured and logged as unverified-platform | - | Pending |
| PLATFORM-08 | P1: Platform profile seam | AC5 — AppArmor flag is Tier-1 profile data; seccomp flag stays profile-independent | - | Pending |
| PLATFORM-09 | P1: Preflight capability probe | AC1 — checks kernel, BTF, cgroup v2, program types as runtime prerequisites | - | Pending |
| PLATFORM-10 | P1: Preflight capability probe | AC2 — missing prerequisite → non-zero exit naming it | - | Pending |
| PLATFORM-11 | P1: Preflight capability probe | AC3 — all prerequisites satisfied → exit zero, no failing prerequisite reported | - | Pending |
| PLATFORM-12 | P1: Preflight capability probe | AC4 — runs without the sidecar binary or container images present | - | Pending |
| PLATFORM-13 | P1: Preflight capability probe | AC5 — verification-time mode checks rootful podman, `tshark`, `tcpdump`, TLS egress | - | Pending |
| PLATFORM-14 | P2: Reproducible VM provisioning | AC1 — provisioning installs every documented prerequisite | - | Pending |
| PLATFORM-15 | P2: Reproducible VM provisioning | AC2 — second run converges without error | - | Pending |
| PLATFORM-16 | P2: Reproducible VM provisioning | AC3 — unfetchable package/image named on failure | - | Pending |
| PLATFORM-17 | P2: Honest platform status tracking | AC1 — no suite evidence → `Planned` in the TDD matrix | - | Pending |
| PLATFORM-18 | P2: Honest platform status tracking | AC2 — `Verified` cites suite, date, and result counts | - | Pending |
| PLATFORM-19 | P2: Honest platform status tracking | AC3 — measured kernel replaces the matrix's expected value | - | Pending |
| PLATFORM-20 | P2: Honest platform status tracking | AC4 — out-of-suite skips listed with their host-side cause | - | Pending |

**ID format:** `PLATFORM-[NUMBER]`

**Phase values:** `-` until a design or tasks artifact exists for the requirement (this feature has `spec.md` only — no `design.md` yet).

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 20 total, 0 mapped to tasks, 20 unmapped ⚠️ (expected — tasks not yet created)

---

## Implicit-Requirement Dimensions Sweep

Large-scope feature: every dimension resolves to a requirement or an explicit `N/A because …`.

| Dimension | Resolution |
| --------- | ---------- |
| Input validation & bounds | PLATFORM-09, PLATFORM-13 — runtime prerequisites (kernel, BTF, cgroup v2, program types) and verification-time prerequisites (rootful podman, `tshark`, `tcpdump`, TLS egress) both validated; PLATFORM-12 bounds what the probe itself may assume is installed |
| Failure / partial-failure states | PLATFORM-03, PLATFORM-06, PLATFORM-10, PLATFORM-16 — missing verification-time prerequisite; unmatched profile fail-fast; missing runtime prerequisite; unavailable provisioning dependency — each named, never silent |
| Idempotency / retry / duplicate handling | PLATFORM-15 — provisioning converges on re-run |
| Auth boundaries & rate limits | N/A because this feature adds no network service, API surface, or caller; privileges remain the existing cap set governed by AD-009/AD-013 |
| Concurrency / ordering | N/A because platform verification is a sequential operator workflow; the sidecar-before-app startup ordering belongs to Feature 03 and is unchanged |
| Data lifecycle / expiry | N/A because this feature creates no new persistent artifacts; capture/keylog retention remains governed by AD-006 |
| Observability | PLATFORM-07, PLATFORM-11, PLATFORM-18, PLATFORM-19, PLATFORM-20 — override announced as unverified, clean exit-zero signal, cited run, measured kernel, recorded out-of-suite skips |
| External-dependency failure | PLATFORM-13, PLATFORM-16 — outbound TLS egress checked before the run rather than surfacing as a mid-suite skip; unreachable package/image named |
| State-transition integrity | PLATFORM-17, PLATFORM-18 — `Planned` → `Verified` only with a cited `./deploy/podman/...` run |
| Portability / configuration surface | PLATFORM-02, PLATFORM-04, PLATFORM-05, PLATFORM-08 — host-specific behaviour lives in profile data; the shared bring-up path keeps only distro-independent settings |

---

## Success Criteria

- [ ] `go test -race -tags='integration e2e' ./deploy/podman/...`: 0 failed, 0 skipped on a clean Ubuntu 24.04 LTS VM whose verification-time prerequisites are all present.
- [ ] Skips outside that suite (e.g. `internal/capture`'s backend-parity test under Ubuntu's packaged-`tcpdump` AppArmor profile) are named with their cause in the evidence record and do not block `Verified`.
- [ ] Ubuntu 24.04's row in the TDD matrix reads `Verified` with a cited run and a measured kernel version; the other five rows still read `Planned`.
- [ ] Adding a stub profile for a non-AppArmor platform requires no change to the shared bring-up logic, and `seccomp=unconfined` is still applied from that shared path.
- [ ] `PLATFORM_PROFILE` selects a profile on a host that detection does not match, and the run logs an unverified-platform override.
- [ ] The preflight probe exits zero on the Tier-1 VM in both modes and exits non-zero naming the prerequisite on a non-conforming host.
- [ ] Re-running provisioning against the same target converges without error.

---

## Dependencies

| Dependency | Why | Status |
| ---------- | --- | ------ |
| Feature 03 Phase 6 — closes CAPTURE-04 (AD-012) | This feature's primary evidence is a 0-failed/0-skipped `./deploy/podman/...` run; while CAPTURE-04 remains open, `TestSmoke_OfflineValidationDecryptsPlaintext` skips, so PLATFORM-01 cannot be satisfied | **Blocking** — must land first; that phase's own scope is under revision, so this dependency is on its outcome (no CAPTURE-04 skip in the suite), not on any particular implementation |
| AD-013 | Defines the six platforms and the Tier-1 reference designation | Done |
