# Experimental combined runtime action

**Pilot only: not approved or ready for rollout.** This action combines
StepSecurity Harden-Runner egress control with a local Falco detector. It is
intended for isolated, disposable GitHub-hosted Ubuntu experiments with
synthetic workloads, not sensitive workloads or production builds.

The detector is **not Falco Actions**. The upstream Falco Actions adapter's
0.39.2 image did not start reliably in an independent diagnostic. This pilot
instead uses its own lifecycle adapter and the official Falco 0.45.2 image
pinned by digest. It loads Falco's default rules and one controlled process
marker rule; detecting that marker does not establish general coverage.

## Example

Use the full commit SHA of this PR's head (or an approved release commit) in
place of `<COMMIT_SHA>`. The repository must be accessible to the caller. Run
this as the first action in a dedicated job, on a fresh GitHub-hosted runner:

```yaml
permissions:
  contents: read

jobs:
  isolated-pilot:
    runs-on: ubuntu-24.04
    steps:
      - name: Start the experimental runtime guard
        uses: pagopa-dx/ss-pilot/.github/actions/combined-runtime@<COMMIT_SHA>
        with:
          egress-policy: block
          disable-telemetry: "true"
          allowed-endpoints: >-
            api.github.com:443 github.com:443
            *.githubusercontent.com:443 *.githubapp.com:443
            *.blob.core.windows.net:443 *.trafficmanager.net:443
            auth.docker.io:443 registry-1.docker.io:443
            *.docker.io:443 *.docker.com:443
      # Only run a controlled, non-sensitive workload here.
```

The endpoints above are a starting point for the pilot, not a complete policy
for an arbitrary job. Use a folded scalar for the space-separated allowlist.
The inputs are `egress-policy` (`audit` or `block`), `allowed-endpoints`
(optional), and `disable-telemetry` (`true` or `false`, default `true`).
Disabling event telemetry does not disable control-plane communication. Audit
mode can still enforce StepSecurity's Global Block List.

The composite references the lifecycle adapter at a separate immutable commit
in this PR's history. Update that pin when changing the adapter; copying only
the composite or deleting access to the pinned commit will break consumers.
The integration workflow calls the composite at an immutable commit in the
same history to exercise remote action resolution. Update its pin when changing
either action; the workflow checks that the tested snapshot matches the
implementation under review.

## Known limitations and risks

- **Do not rely on a step-level `if` to disable the firewall.** A prior
  GitHub-hosted experiment showed that Harden-Runner's nested `pre` ran in
  block mode even when the composite step was skipped. Use separate jobs.
  Input validation in the composite runs after that pre-step and cannot prevent
  it from acting on invalid input.
- The adapter uses a privileged Docker container, the host Docker socket,
  host `/proc` and `/etc`, and tracefs. It is not a least-privilege design.
  Falco events may contain sensitive process data; perform a privacy and
  retention review before considering non-synthetic workloads.
- Startup requires a matching native event for an exact marker PID; the post
  step stops and removes only the recorded container. This is not continuous
  supervision or fail-closed protection: the detector can die during a job.
  A crash between container creation and recording its ID can leave an
  unowned container, which cleanup refuses to remove. A hard runner
  termination may prevent the post step from running.
- A controlled prior test observed firewall denial and a native Falco event
  together. It does not establish full detection coverage, production
  reliability, or performance. Egress enforcement also has a known shared-IP
  hostname limitation that needs separate assessment.
- Self-hosted runners require Harden-Runner Enterprise, including for public
  repositories; without it the action can succeed without monitoring.
  Compatibility with self-hosted Azure Container Apps runners is **unverified**.
  No self-hosted deployment design or DX/Azure change is included here.

Rule selection, privileges, network access, support, privacy, supervision and
the conditional pre-step behavior must be addressed before any rollout.

## Reproduce the coexistence controls

The existing Node build workflow dispatches an independent coexistence harness
from the selected branch. It uses the fixture, bootstrap, workload and evidence
helpers already on `main`; it does not require the general benchmark workflow.
Run only on disposable GitHub-hosted runners:

```shell
gh workflow run node-build-pilot.yml --ref YOUR_BRANCH \
  -f coexistence-profile=coexistence
```

The `coexistence` profile runs four separate jobs: baseline, firewall only,
detector only, and the combined action. They check the controlled build and
dependency request, and correlate the Falco marker to its PID when enabled.
The workflow saves pre-cleanup evidence artifacts for seven days; review their
contents and retention before using any non-synthetic workload.

Additional profiles are `coexistence-failure`, `coexistence-cancel`,
`coexistence-conditional`, and `coexistence-diagnostic`. The failure profile
deliberately fails two jobs; inspect their post steps rather than interpreting
the red run as a regression. The cancellation profile waits for an explicit
external cancellation after `PILOT_CANCEL_READY`; cancellation or hard runner
termination can prevent cleanup. The conditional profile observes the known
nested pre-step behavior. The diagnostic profile includes the upstream older
image, which previously failed, so it may intentionally produce a failed job.

The harness pins both remote actions to commits in this PR's history, while its
local helpers come from the checked-out branch. Update those pins alongside
the action and workflow test pins when revising the implementation. A passing
control is an observation for that runner and workload, not a rollout approval.
