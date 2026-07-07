# OpenShift Virtualization (CIS VM Extension) e2e

The OCP-Virt profiles (e.g. `cis-vm-extension`) are **CEL** profiles that check
OpenShift Virtualization resources. Running them e2e differs from the SCAP profiles in
two ways, both handled by this suite:

1. **The cluster needs OpenShift Virtualization (CNV) installed.** CI clusters (e.g.
   `ipi-aws`) do not ship CNV, so the suite can install it during setup.
2. **The profile is delivered via a CEL content file**, not the XCCDF datastream, so the
   ProfileBundle needs `spec.celContentFile` set.

## Flags

| Flag | Make var | Default | Purpose |
|------|----------|---------|---------|
| `-install-virt` | `INSTALL_VIRT` | `false` | Install the CNV operator + `HyperConverged` CR during setup. Idempotent; no-ops if CNV is already present. |
| `-cel-content-file` | `CEL_CONTENT_FILE` | `""` | Path (inside the content image) to the CEL content YAML, e.g. `ocp4-cel-content.yaml`. When set, a CEL ProfileBundle is created so CEL profiles are parsed. |

## Running locally

```bash
# 1. Build the content image with the CEL content bundle:
#    (in the ComplianceAsCode/content checkout)
./build_product ocp4 --datastream --cel-content=ocp4
#    -> build/ssg-ocp4-ds.xml and build/ocp4-cel-content.yaml
#    Package both into an image and push it to a registry the cluster can pull.

# 2. Run the OCP-Virt profile e2e against a cluster (installs CNV itself):
export PROFILE=cis-vm-extension
export PRODUCT=ocp4
export INSTALL_VIRT=true
export CEL_CONTENT_FILE=ocp4-cel-content.yaml
make e2e-profile TEST_FLAGS="-v -timeout 120m" \
  # go test also needs -content-image=<your image>
```

`make e2e-profile` runs `TestProfile` with `-install-virt=$(INSTALL_VIRT)` and
`-cel-content-file="$(CEL_CONTENT_FILE)"`.

## What the CNV install step does

`installVirtualizationOperator` (`helpers/virtualization.go`), gated on `-install-virt`:

1. Creates the `openshift-cnv` namespace, an OperatorGroup, and a Subscription for
   `kubevirt-hyperconverged` (channel `stable`, source `redhat-operators`).
2. Waits for the `HyperConverged` API to be served.
3. Creates the `HyperConverged` CR (retrying to tolerate the operator webhook not being
   ready immediately) and waits until it reports `Available`.

An opt-in live test exercises just this path:

```bash
RUN_VIRT_LIVE=1 go test ./helpers -run TestInstallVirtLive -timeout 40m -v
```

## Proposed CI lane (openshift/release)

A lane for the profile mirrors the existing `e2e-aws-ocp4-*` entries, adding the two
env vars:

```yaml
- as: e2e-aws-ocp4-cis-vm-extension
  steps:
    cluster_profile: quay-aws
    test:
    - as: test
      commands: |
        export PROFILE=cis-vm-extension PRODUCT=ocp4
        export INSTALL_VIRT=true CEL_CONTENT_FILE=ocp4-cel-content.yaml
        make e2e-profile
    workflow: ipi-aws
```

(The release-repo change is tracked separately; it depends on this PR's Makefile wiring.)

## Validation

Verified on an OCP 4.21 + AWS cluster:

- `TestInstallVirtLive` installs CNV and `HyperConverged` reaches `Available` in ~4 min
  (no metal nodes required for the operator/HCO config that the CEL rules read).
- With a CEL content image, a ProfileBundle using `celContentFile: ocp4-cel-content.yaml`
  parses `VALID` and the operator creates the `cis-vm-extension` CEL profile and its
  `scannerType: CEL` rules; a ScanSettingBinding runs the scan to completion and produces
  per-rule `ComplianceCheckResult`s.
