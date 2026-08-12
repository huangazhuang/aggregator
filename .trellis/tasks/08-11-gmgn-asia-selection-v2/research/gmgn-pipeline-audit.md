# Research: GMGN pipeline audit

> Historical audit snapshot: findings describe the pre-V2 code and are evidence, not the target contract. Current requirements live in the parent/child task artifacts and `gmgn-v2-contract.md`.

- Query: Audit `.cnb.yml`, `scripts/cnb_gmgn_shadow.py`, `scripts/cnb_gmgn_publish.py`, and related utilities for a Guangdong-CNB, all-candidate, 20-round GMGN selection pipeline, including correctness, performance, history, timeout/error accounting, privacy, egress/region, diversity, groups, and failure/rollback behavior.
- Scope: mixed (repository code, tests, project documentation, and current public redacted CNB outputs)
- Date: 2026-08-11

## Findings

### Executive assessment

The single-run probing core is substantially hardened: it pins a fresh source by SHA, deterministically balances four shards, gives every proxy in that source exactly one attempt per round for exactly 20 rounds, treats `1000 ms` as a pass and `1001 ms` as slow, checks Mihomo health after each round, validates all four fragments, keeps full proxy material out of the shadow branch, and validates the final Clash file before force-pushing it. The current public run confirms the four-way parallel layout is effective: 2,260 source proxies (45,200 attempts) completed with shard durations of roughly 1,388–1,452 seconds.

The pipeline does **not** yet satisfy the stronger multi-run/region/diversity contract in the dispatch request. The principal blockers are:

1. Guangdong/China egress is observed but never enforced.
2. “Asia” is a source-label heuristic, so a mislabeled non-Asia proxy can receive relaxed Asia treatment.
3. The pipeline has no durable 2–3-run history and no cross-run anonymous node identity; both output branches are rewritten as one-commit snapshots.
4. The publisher cannot see normalized error categories or round-wide failure patterns, so it cannot distinguish a bad candidate population from a target/runner-wide incident before replacement.
5. “Every candidate” means every proxy in the already filtered `clash-verge-output`, not every collected/crawled candidate.
6. There is no explicit endpoint/provider/ASN/protocol/source diversity policy.

### Requirement matrix

| Requirement | Assessment | Evidence |
|---|---|---|
| Exactly 20 GMGN rounds | Pass for every proxy that reaches the GMGN source snapshot | Formal settings require exactly 20 rounds (`scripts/cnb_gmgn_shadow.py:626-644`); every round submits every shard proxy (`scripts/cnb_gmgn_shadow.py:537-606`); incomplete records abort (`scripts/cnb_gmgn_shadow.py:1031-1035`). |
| `<=1000 ms` is a pass | Pass | Inclusive comparison is used in both summaries and per-round trends (`scripts/cnb_gmgn_shadow.py:484-525`, `scripts/cnb_gmgn_shadow.py:584-589`); boundary tests exist (`tests/test_cnb_gmgn_shadow.py:98-112`). |
| Practical parallelism | Pass for the present one-runner design, with no adaptive control | Four concurrent jobs use distinct controllers/ports (`.cnb.yml:382-443`), each with 16 workers (`.cnb.yml:342-349`); sharding is deterministic and count-balanced (`scripts/cnb_gmgn_shadow.py:314-326`). Current live shard durations differed by only about 4.6%. |
| Every candidate | Partial / scope mismatch | GMGN reads the already published `clash-verge-output` (`.cnb.yml:330-331`), after GitHub merge, GFW probe, and GMGN/Google/YouTube reachability filtering (`.github/workflows/clash-verge-auto.yml:244-259`, `scripts/filter_reachability.py:84-89`, `scripts/filter_reachability.py:118-175`). |
| Guangdong runner | Observed now, not guaranteed | Runner selector only says AMD64 (`.cnb.yml:317-320`). Geo lookup is best-effort and may return blanks (`scripts/cnb_mihomo_filter.py:204-249`); the manifest only requires four strings, not China/Guangdong (`scripts/cnb_gmgn_shadow.py:849-853`). |
| Asia protected/observed over 2–3 runs | Fail | Only the immediately preceding stable/observation memberships are loaded (`scripts/cnb_gmgn_publish.py:517-619`); random IDs are regenerated per run (`scripts/cnb_gmgn_shadow.py:1036-1051`); both branches are force-replaced from fresh repositories (`.cnb.yml:477-485`, `.cnb.yml:551-559`). |
| Non-Asia strict | Partial | Total pass thresholds are strict (16/20 base, 18/20 expansion), but there is no half/block/tail-stability check (`scripts/cnb_gmgn_publish.py:688-704`). Misclassified non-Asia can enter Asia tiers. |
| Manual testing exposure | Pass, with auto-group leakage | `手动选择` exposes every selected node (`scripts/cnb_gmgn_publish.py:770-781`), but `GMGN自动` also includes flexible and observation nodes (`scripts/cnb_gmgn_publish.py:758-805`). |
| No quota filling; 80 desired, 150 maximum | Pass in the basic selector | `80` is diagnostics only and `150` is the cap (`scripts/cnb_gmgn_publish.py:65-70`, `scripts/cnb_gmgn_publish.py:906-909`); no fallback nodes are added. However, the rollback floor counts low-confidence manual tiers the same as stable nodes. |
| Privacy | Mostly pass | Private fragments are constrained to `.cnb-runtime` and written mode `0600` (`scripts/cnb_gmgn_shadow.py:903-924`, `scripts/cnb_gmgn_shadow.py:1075-1103`); Mihomo startup logs are suppressed on errors (`scripts/cnb_gmgn_shadow.py:462-481`); public result fields are exact and redacted (`scripts/cnb_gmgn_shadow.py:1185-1203`, `scripts/cnb_gmgn_shadow.py:1620-1635`). |
| Last-good rollback | Partial pass | Build/count/profile failures occur before the final branch push (`scripts/cnb_gmgn_publish.py:845-958`, `.cnb.yml:519-535`), but cross-branch history and concurrent force-push safety are incomplete. |

### P1 — Runner geography is telemetry, not a publication invariant

- `.cnb.yml:317-320` requests `cnb:arch:amd64`; it contains no China, Guangdong, provider, or egress selector.
- `discover_runner_network()` explicitly calls its lookup “best-effort” and treats failure as non-fatal, returning empty country/region/org fields (`scripts/cnb_mihomo_filter.py:204-249`).
- Preparation records one lookup in the manifest (`scripts/cnb_gmgn_shadow.py:733-755`), while each probing shard does not independently re-check its own egress (`scripts/cnb_gmgn_shadow.py:927-1022`).
- Manifest validation accepts any strings, including empty values (`scripts/cnb_gmgn_shadow.py:849-853`), and the publisher likewise validates shape only (`scripts/cnb_gmgn_publish.py:335-339`).

The current public run reported `China / Guangdong Sheng / Tencent cloud computing Beijing Co., Ltd.`, so the desired location happened in the observed run. There is no fail-closed control preventing a later run from publishing from another province/country, nor proof that all four job networks match the preparation-stage lookup. A formal Guangdong requirement needs a hard allowlist and per-probe-shard consistency evidence, not only status metadata.

### P1 — Label-based Asia classification can weaken the non-Asia policy

- The project explicitly states that egress region is not verified (`scripts/cnb_gmgn_shadow.py:54`, `scripts/cnb_gmgn_publish.py:71`).
- `is_preferred_asian_proxy()` checks user/source-controlled `name`, `country`, `region`, and `location` strings (`subscribe/asia.py:53-75`).
- The short-name regex accepts single characters including `新` (`subscribe/asia.py:26-30`). A generic label such as `新-01` (“new 01”) can therefore be treated as Singapore even if the actual exit is elsewhere. Flags, codes, and city text are similarly trusted without an exit-IP check (`subscribe/asia.py:10-24`, `subscribe/asia.py:65-75`).
- That boolean directly selects relaxed Asia rules (`scripts/cnb_gmgn_publish.py:666-691`): 10–13/20 can be exposed as flexible, and 14/20 with half-window balance can enter stable, instead of the non-Asia 16/20 or 18/20 thresholds.

This is not only a reporting caveat; it changes eligibility. Until actual exit verification exists, “non-Asia strict” is only “labels not recognized as preferred Asia strict.” At minimum, ambiguous short markers should not grant relaxed policy without stronger evidence.

### P1 — There is no durable 2–3-run history or cross-run node observation

- Shadow node IDs are random per run (`scripts/cnb_gmgn_shadow.py:1036-1051`), and the generated README explicitly says they cannot be tracked across runs (`scripts/cnb_gmgn_shadow.py:1528-1529`).
- The publisher reconstructs history only from the immediately preceding public profile’s `GMGN稳定` and `GMGN观察保留` memberships (`scripts/cnb_gmgn_publish.py:517-619`). It stores no prior run ID, prior per-node counts, streak, or 3-run window.
- The shadow branch and profile branch are each created with `git init`, one commit, and `git push --force` (`.cnb.yml:477-485`, `.cnb.yml:551-559`). Thus branch history itself cannot supply the missing run window.
- Current publish status stores a single `previous_published_count` but not a history collection (`scripts/cnb_gmgn_publish.py:884-952`).

Consequences:

- Users cannot compare the same anonymous candidate across 2–3 shadow runs.
- The selector cannot require “passed in 2 of 3 runs,” a stability streak, or a bounded degradation trend.
- A later run permanently removes the earlier redacted report from the raw branch URL.

Aggregate history can be retained without weakening redaction (for example, last-three run summaries). Node-level history needs a private stable identity or keyed pseudonym; a raw stable SHA-256 of a proxy configuration should not be published because the input space may be guessable.

### P1 — The current one-run “hysteresis” is mostly a label/priority change, not retention

- A previous stable Asia node at 12–13/20 is put in `observation` (`scripts/cnb_gmgn_publish.py:676-683`).
- But every Asia node at 10–13/20 is already eligible for `asia_flexible` (`scripts/cnb_gmgn_publish.py:684-687`).
- Observation nodes are selected before flexible nodes only when the 150-node cap constrains capacity (`scripts/cnb_gmgn_publish.py:706-714`).
- On the next run, a prior observation node at 12–13/20 simply falls back into flexible (`tests/test_cnb_gmgn_publish.py:417-447` documents this intended behavior).

Therefore the mechanism changes the group label and gives cap priority, but below the cap it does not keep a node that would otherwise disappear. It does not implement protection over 2–3 runs. If the goal is true hysteresis, the normal core/flexible thresholds and the history/streak contract need to make the retained state behaviorally distinct.

### P1 — The publisher is blind to systemic GMGN/runner error modes

- The redacted shadow fragment has `round_trends` and normalized `error_counts` (`scripts/cnb_gmgn_shadow.py:95-116`, `scripts/cnb_gmgn_shadow.py:1052-1071`).
- The private selection fragment passed to the publisher deliberately omits both fields (`scripts/cnb_gmgn_shadow.py:161-179`, `scripts/cnb_gmgn_shadow.py:1075-1101`; mirrored in `scripts/cnb_gmgn_publish.py:39-57`).
- Candidate selection looks only at per-node counts/latencies (`scripts/cnb_gmgn_publish.py:647-726`). The replacement gate is only `max(10, ceil(previous_count * 0.40))` selected nodes (`scripts/cnb_gmgn_publish.py:857-868`).

As a result, publication cannot reject a run because of a global 403/429 burst, a runner DNS/TLS incident, abnormal shard-wide timeouts, or a sharp control-target regression, as long as enough nodes still cross tier thresholds. There is also no direct/control request per round to distinguish target availability from candidate quality.

The live 2026-08-11 shadow status illustrates why this data path matters: of 45,200 attempts, 38,809 (85.86%) were no-result, split into 24,474 `timeout` and 14,335 `controller_5xx`; 5,514 were slow and 877 were within 1000 ms. This does **not** prove a bad publication—the free-proxy population may simply be poor—but the publisher had no access to the error mix with which to make that judgment.

### P1 — A failed profile publication breaks cross-branch run correlation

The stage order is:

1. merge run B shadow data (`.cnb.yml:445-460`),
2. force-publish shadow run B (`.cnb.yml:463-485`),
3. only then fetch history, apply the floor, build, and validate the priority profile (`.cnb.yml:489-535`).

If step 3 refuses publication, the priority branch correctly keeps last-good profile A, but the shadow branch has already discarded report A and now shows B. Profile A’s `run_id` can no longer be resolved to its supporting shadow report. This undermines rollback auditability precisely on degraded/failing runs. Content-addressed run artifacts or a retained last-N index are needed; merely keeping the old profile branch is insufficient history.

### P1/P2 — “Every candidate” is currently a post-filter subset, with asymmetric cohort bias

- The GMGN source is `clash-verge-output/clash.yaml` (`.cnb.yml:330-331`).
- Before that branch is published, candidates are merged, optionally GFW-probed, and filtered for GMGN, Google, and YouTube reachability (`.github/workflows/clash-verge-auto.yml:244-259`, `scripts/filter_reachability.py:84-89`, `scripts/filter_reachability.py:121-175`).
- Preferred-Asia labels bypass those GitHub network checks, while ordinary nodes must pass all targets (`scripts/filter_reachability.py:60-81`, `scripts/filter_reachability.py:118-175`).

The GMGN loop does test every proxy **inside that final profile**, and no 3-round candidate truncation remains. It does not test every proxy originally collected/crawled. It also starts with different upstream inclusion rules for Asia and non-Asia, which biases capacity/history comparisons. If “every candidate” means the raw merged universe, the source snapshot must be moved to a pre-reachability, config-valid stage (with provenance and secure handling).

### P2 — No diversity policy or provenance survives into selection

- Merge concatenates collected and crawled proxy dicts and writes a flattened profile (`scripts/merge_clash_profiles.py:18-52`). Source/provider provenance is not attached.
- Upstream `clash.filter_proxies()` performs exact-ish endpoint/credential deduplication, but it is not a failure-domain diversity policy (`subscribe/clash.py:67-134`, `subscribe/clash.py:137-175`).
- The GMGN publisher rejects duplicate **names** but not duplicate fingerprints, endpoints, hosts, ASN/provider, protocol, or source (`scripts/cnb_gmgn_publish.py:428-455`).
- Ranking is a global quality sort with fingerprint as the final tie-breaker (`scripts/cnb_gmgn_publish.py:622-637`), and selection simply slices those rankings (`scripts/cnb_gmgn_publish.py:647-726`).

Current public profile aggregate (credentials and endpoint values not recorded here): 26 nodes, 20 unique server strings, 20 unique server/port pairs, and as many as 4 selected nodes on one server/port; protocol counts were AnyTLS 5, HTTP 2, Hysteria2 1, SOCKS5 1, Trojan 3, TUIC 8, and VLESS 6. The present output is not catastrophically homogeneous, but that is incidental. A future high-quality cluster can consume most slots and create a single-host/ASN/provider failure domain.

Practical diversity requires provenance before flattening plus explicit caps/soft penalties (for example per server, server/port, ASN/provider, source subscription, protocol, and region), applied without admitting below-threshold nodes.

### P2 — Flexible and observation nodes participate in automatic selection

- `all_names` contains stable, observation, and flexible selected nodes (`scripts/cnb_gmgn_publish.py:744-761`).
- `GMGN自动` receives all of them (`scripts/cnb_gmgn_publish.py:799-805`).

That conflicts with a “protect/observe and expose for manual testing” interpretation: a 10/20 flexible node can become the automatically chosen route after one local URL test. If flexible/observation tiers are evidence-gathering/manual tiers, `GMGN自动` should normally contain only stable nodes; manual group can continue to expose every tier.

### P2 — The rollback floor treats manual/weak tiers as equal to stable tiers

- `published_count` is the length of `stable + observation + flexible` (`scripts/cnb_gmgn_publish.py:713-725`, `scripts/cnb_gmgn_publish.py:857-868`).
- The first-publish floor is only 10, and later runs require 40% of the previous total (`scripts/cnb_gmgn_publish.py:65-68`, `scripts/cnb_gmgn_publish.py:857-868`).

Therefore ten 10/20 flexible Asia candidates can satisfy first publication with zero stable nodes, or a weak-tier-heavy run can satisfy the numeric replacement floor while stable capacity collapses. `GMGN稳定` then falls back to `DIRECT` if empty (`scripts/cnb_gmgn_publish.py:763-787`), even though the overall status says publication succeeded. A quality-preserving rollback gate should consider stable count/tier mix (and perhaps weighted quality), not only total selected nodes.

### P2 — Non-Asia strictness has no temporal stability requirement

The private summary computes half and four five-round block counts (`scripts/cnb_gmgn_shadow.py:484-525`), but non-Asia selection uses only total `within_limit_count` (`scripts/cnb_gmgn_publish.py:688-704`). A node with 16 successes early and four consecutive tail failures still qualifies for the base non-Asia tier. Asia core already guards against one-sided runs. If “strict” includes sustained availability, non-Asia needs a half/block/tail condition too; otherwise document that strictness means only total-count strictness.

### P2 — Error categories are internally consistent but diagnostically coarse

- Classification recognizes only a few error-text shapes; connection failures only match `connection refused` or `connection reset`, with many DNS/TLS/EOF/network failures falling into `controller_5xx` or `other` (`scripts/cnb_gmgn_shadow.py:329-352`).
- Counts are rigorously reconciled with no-result totals (`scripts/cnb_gmgn_shadow.py:1409-1418`), so accounting quantity is sound.
- The category name `controller_5xx` can be misread as a Mihomo infrastructure crash even when the controller is healthy and returns 5xx for a per-proxy request; separate health checks already cover actual controller death (`scripts/cnb_gmgn_shadow.py:443-459`, `scripts/cnb_gmgn_shadow.py:597-603`).

The live run’s 14,335 `controller_5xx` events show the taxonomy is too broad for operational decisions. Normalize safe aggregate reasons such as DNS, TLS, connect, proxy-auth, target-status, client-timeout, and controller-unhealthy without publishing raw error text.

### P2 — Force-push concurrency protection is not compare-and-swap

- The job lock queues normal pipeline runs (`.cnb.yml:323-328`), which is useful.
- Build checks the previous branch and writes its ref output to a file, but does not parse or retain the tip SHA (`.cnb.yml:499-513`).
- Final publication uses unconditional `git push --force` (`.cnb.yml:557-559`), not `--force-with-lease` against the tip used for history/floor calculation.

An external/manual write, a lock-expiry overlap, or any second publisher outside this lock can let an older run overwrite a newer good run after using stale previous history. Capture the observed branch tip and publish with a lease; also reject a run older than the current status/run timestamp.

### P2 — The diagnostic shadow push is on the profile’s critical path

`Publish the isolated GMGN shadow report` runs before profile build (`.cnb.yml:463-489`) and is not marked optional. A transient push failure on the diagnostics branch prevents an otherwise valid selection/profile refresh. Branch isolation protects data from mutual overwrite, but availability remains coupled. If the priority profile is the primary deliverable, build/validate both artifacts first and publish them with independently reported outcomes, or make the diagnostic publication retryable/non-blocking under an explicit policy.

### P3 — Runtime reproducibility is tied only indirectly to `main_sha`

The checked-in `clash/clash-linux-amd` used for this audit had SHA-256 `08df1464bde7d16936ad086a29b12c435fc6b1cf6554d3b7669433fc13f6fc68`, but the manifest/status does not record the executable hash or Mihomo version (`scripts/cnb_gmgn_shadow.py:118-159`). Health checks call `/version` and discard the response (`scripts/cnb_gmgn_shadow.py:443-459`). `main_sha` indirectly pins the repository binary, but recording version/hash in each run would make 2–3-run comparisons and incident diagnosis explicit.

### P3 — Shared publication-floor logic is duplicated

`scripts/pipeline_utils.py:91-100` already owns `calculate_publish_floor()`, while GMGN publication recomputes the formula inline (`scripts/cnb_gmgn_publish.py:857-862`). The current formulas agree, but duplication creates policy-drift risk across gstatic, reachability, and GMGN publishers. This is directly relevant because rollback thresholds are safety contracts.

### What is already correct and should be preserved

- **Formal target contract:** exact `https://gmgn.ai/`, HTTP 200, request timeout 3000 ms, qualified delay 1000 ms, and exactly 20 rounds are enforced before probing and again in the strict shadow manifest (`scripts/cnb_gmgn_shadow.py:626-644`, `scripts/cnb_gmgn_shadow.py:778-825`).
- **No early candidate truncation inside the GMGN snapshot:** every shard proxy is submitted every round (`scripts/cnb_gmgn_shadow.py:537-606`). A timeout in one round does not remove the node from later rounds.
- **Fair, stable sharding:** configuration fingerprint sorting plus round-robin partition is input-order independent and balances shard counts (`scripts/cnb_gmgn_shadow.py:299-326`; covered by `tests/test_cnb_gmgn_shadow.py:347-369`). Rotation changes queue order each round (`scripts/cnb_gmgn_shadow.py:560-572`).
- **Capacity guard:** worst-case batches are estimated before launch (`scripts/cnb_gmgn_shadow.py:661-713`). The configured 6,600-second budget is below the 120-minute shard timeout (`.cnb.yml:347-349`, `.cnb.yml:382-443`).
- **Infrastructure failures do not silently become completed nodes:** process/controller health is rechecked every round, and incomplete records abort (`scripts/cnb_gmgn_shadow.py:443-459`, `scripts/cnb_gmgn_shadow.py:597-605`, `scripts/cnb_gmgn_shadow.py:1031-1035`).
- **Fragment integrity:** manifest, shard hashes, exact fragment fields, per-round totals, per-node totals, half/block totals, and error totals are checked (`scripts/cnb_gmgn_shadow.py:778-888`, `scripts/cnb_gmgn_shadow.py:1298-1418`, `scripts/cnb_gmgn_shadow.py:1535-1564`).
- **Shadow privacy:** full proxy configs stay in private selection fragments; public node records contain no name/server/port/credential/raw-error/per-round sample fields (`scripts/cnb_gmgn_shadow.py:61-80`, `scripts/cnb_gmgn_shadow.py:1075-1103`, `scripts/cnb_gmgn_shadow.py:1620-1635`). Runner IP/city are removed while coarse country/region/org are retained (`scripts/cnb_gmgn_shadow.py:431-440`).
- **Basic last-good protection:** previous profile/status are fetched fail-closed, profile SHA/count/group references are verified, and malformed/missing prior state stops replacement (`scripts/cnb_gmgn_publish.py:467-619`). New output is rendered, parsed, hashed, and then checked by Mihomo before the final push (`scripts/cnb_gmgn_publish.py:845-958`, `.cnb.yml:531-535`).
- **No quota filling:** only threshold-qualified candidates enter the output; `desired_capacity` is status metadata (`scripts/cnb_gmgn_publish.py:647-726`, `scripts/cnb_gmgn_publish.py:906-909`).
- **Manual exposure:** the manual group lists all selected node names after the tier groups (`scripts/cnb_gmgn_publish.py:770-781`).

### Test coverage gaps

Existing tests are strong on single-run arithmetic, exact formal parameters, privacy paths/modes, shard completeness, fragment consistency, previous-profile fail-closed behavior, count floor, and group presence (`tests/test_cnb_gmgn_shadow.py`, `tests/test_cnb_gmgn_publish.py`). Missing regression/integration contracts include:

- hard China/Guangdong allowlist and per-shard egress consistency;
- ambiguous/false-positive Asia labels and actual-exit mismatch;
- retained last-three run summaries and node streak semantics;
- a test proving observation changes survival, not merely group label;
- target-wide 403/429/timeout/controller-failure circuit breaking;
- stable-tier minimum/weighted rollback floor;
- flexible/observation exclusion from the auto group (if manual-only is intended);
- duplicate fingerprint/server/server-port/ASN/provider/source caps;
- force-with-lease and stale-run rejection;
- cross-branch correlation after a refused profile publication;
- a clear fixture proving whether “every candidate” starts before or after the GitHub reachability filter;
- live or contract testing of the Mihomo `expected=200` delay-endpoint behavior for the pinned binary.

### Files found

- `.cnb.yml` — CNB runner, lock, source, four-shard jobs, and two force-published output branches.
- `scripts/cnb_gmgn_shadow.py` — source pinning, sharding, 20-round probe execution, redaction, validation, and shadow merge.
- `scripts/cnb_gmgn_publish.py` — previous-profile history extraction, region-tier selection, groups, count floor, and publication status.
- `scripts/cnb_mihomo_filter.py` — shared source loading, runner geo lookup, Mihomo API helpers, and name normalization.
- `scripts/pipeline_utils.py` — shared Clash serialization and publication-floor utility.
- `subscribe/asia.py` — preferred-Asia label heuristic used by both probe and publisher.
- `scripts/merge_clash_profiles.py`, `subscribe/clash.py`, `scripts/filter_reachability.py` — upstream candidate flattening, dedupe, provenance loss, and pre-GMGN filtering.
- `.github/workflows/clash-verge-auto.yml` — produces the already-filtered GMGN source branch.
- `.github/workflows/sync-cnb.yml` — main-only GitHub-to-CNB trigger/tag flow.
- `tests/test_cnb_gmgn_shadow.py`, `tests/test_cnb_gmgn_publish.py` — current single-run and workflow regression coverage.
- `CNB_SETUP.md`, `CLASH_VERGE_AUTO.md` — published behavior claims and current intended policy.

### External references and observed versions

- Current shadow status (read 2026-08-11): `https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-shadow/status.json`
  - run `shadow_fb51c0826aefc8d24cfdb73cf68c0750`, source 2,260, preferred-Asia labels 1,163;
  - runner reported China / Guangdong Sheng / Tencent cloud computing Beijing Co., Ltd.;
  - shard durations 1,434.45 / 1,432.73 / 1,451.99 / 1,388.37 seconds;
  - 45,200 attempts: 877 within 1000 ms, 5,514 slow responses, 38,809 no-result.
- Current priority status (read 2026-08-11): `https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/status.json`
  - same run ID; 26 published: stable 21, Asia flexible 5, observation 0; previous count 12, required floor 10.
- Runtime image and Python dependency are pinned in `.cnb.yml:321-355`: `python:3.12-bookworm`, `PyYAML==6.0.2`.
- Mihomo binary present in the audited checkout: `clash/clash-linux-amd`, 48,840,830 bytes, SHA-256 `08df1464bde7d16936ad086a29b12c435fc6b1cf6554d3b7669433fc13f6fc68`.

### Related specs

- `.trellis/spec/guides/cross-layer-thinking-guide.md` — relevant because source snapshot → manifest → private/redacted fragments → publisher → branch status is a multi-boundary data contract; error/history fields currently stop before the publisher.
- `.trellis/spec/guides/code-reuse-thinking-guide.md` — relevant to duplicated publication-floor/fingerprint/validation contracts.
- At audit time, `.trellis/spec/manager/backend/index.md`, `error-handling.md`, `logging-guidelines.md`, and `quality-guidelines.md` were placeholders and provided no project-specific GMGN safety contract. Planning subsequently added `.trellis/spec/aggregator/` and made it the default package.
- At audit time, `.trellis/tasks/08-11-gmgn-asia-selection-v2/prd.md` was an empty template. The completed PRD/design/implementation artifacts now supersede that planning gap; this paragraph remains only as timestamped audit context.

## Caveats / Not Found

- No product code or configuration was modified, and no git operation was performed.
- Unit tests were inspected but not executed in this research role; several tests create temporary files, while this role is restricted to writing only under the active task’s `research/` directory.
- The public live status is mutable and may show a later run when revisited; exact values above are the 2026-08-11 observation recorded during this audit.
- CNB’s internal scheduler/network-isolation semantics were not available as a versioned repository contract. The code and current live run demonstrate that the four jobs complete in parallel, but only CNB documentation/metadata can prove whether every job is guaranteed to share one physical runner/egress.
- A GitHub code-search attempt for the upstream Mihomo `expected` delay-query contract hit an API rate limit. The local pipeline passes `expected=200`, and current behavior is exercised live, but the repository does not pin an upstream API-contract reference or integration fixture.
