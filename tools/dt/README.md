# oidc-provider DefinitelyTyped release handoff

The provider owns the release synchronization tools in `tools/dt`, the declaration
sources in `types`, and the generated configuration contracts. The schema 3
artifact includes the client authentication methods and complete `OIDCContext`
declaration, the grant helper declarations, and the DT test suite. Synchronization
tools stay in provider and the downloaded release bundle.

## Provider development

Edit and commit declaration templates and tests in the provider's `types/`
directory alongside the runtime change. Regenerate provider documentation as
described in [the declaration source guide](https://github.com/panva/node-oidc-provider/blob/main/types/README.md).

Do not synchronize or commit a sibling DefinitelyTyped checkout during provider
development, even when it is available and writable. Unreleased provider changes
are expected to differ from DT; an exact mirror check against provider HEAD is
not a development gate. A request to change or commit provider code does not
authorize a DT update.

DT synchronization is a separate, explicitly requested task after a provider
release. Use the released tag's handoff bundle and `sync-release.mjs` below.
Do not use an unreleased provider checkout to prepare a DT release update, and
do not edit generated DT declaration regions or the mirrored test file by hand.

## Release synchronization

After publishing the provider release, the release workflow checks DT using
declarations and tests from the released tag. When an update is required, it
uploads `oidc-provider-types-vX.Y.Z` and prints the handoff commands in the job
summary. The workflow does not commit or submit changes to DT.

For the requested DT synchronization, download that complete artifact. It
contains exactly `oidc-provider-types.json`,
`update-types.mjs`, `update-types.test.mjs`, `sync-release.mjs`,
`sync-release.test.mjs`, and `README.md`. Run its portable helper against your DT
checkout:

```sh
node /path/to/bundle/sync-release.mjs \
  --repository /path/to/DefinitelyTyped \
  --tag v9.13.0 \
  --artifact /path/to/bundle/oidc-provider-types.json
```

The helper also accepts `--run-id 123456789` instead of `--artifact` to download
the exact named artifact from `panva/node-oidc-provider`. Downloads must contain
the JSON alone or the complete flat tooling bundle; extra files, directories,
and symlinks are rejected. The helper requires an explicit `--repository` path.

Before changing anything, synchronization verifies GitHub CLI authentication,
the `origin` fork and official `upstream` remote, Git author identity, Node.js,
and pnpm. The authenticated GitHub user must own `origin`.

The helper fetches `upstream/master`, creates a temporary Git worktree, installs
only the root tooling and `@types/oidc-provider` dependency closure with a
no-lockfile workspace install, and checks whether the release needs an update.
It always invokes its companion updater and tests from provider or the downloaded
bundle. It does not depend on scripts in DT. A required update runs:

- the updater's exact `--check`;
- the updater artifact/status integration checks;
- the synchronization orchestration tests;
- dprint over `types/oidc-provider`;
- `pnpm test oidc-provider`.

The updater's reported file list must exactly match Git, and every change must
remain within the fixed managed files in `types/oidc-provider`. Successful
preparation leaves one local commit on `oidc-provider-vX.Y.Z`, titled
`[oidc-provider] sync declarations for vX.Y.Z`, and removes the temporary
worktree. Inspect and submit the branch using the commands printed by the
helper. The submission command reruns validation with the same artifact source.

Pass `--submit` to push without force and open a draft PR against
`DefinitelyTyped/DefinitelyTyped:master`. Its body is the unchanged default
`.github/PULL_REQUEST_TEMPLATE.md` from the DT checkout; fill it in after the
draft is created. Existing open or merged PRs for the release branch are
successful no-ops. Closed, unmerged PRs and remote branches without a PR require
manual recovery. A matching prepared local branch can be reused safely.

Temporary state is preserved on failure. Pass `--keep-temp` to preserve it after
success as well. Run the focused orchestration tests separately with:

```sh
node --test /path/to/bundle/sync-release.test.mjs
```

## Low-level updater and tooling checks

`update-types.mjs` is used by the release helper. It also accepts a provider
checkout for tooling development and diagnostics; that interface is not the
release synchronization workflow. Running it without `--check` or `--status`
writes to the target package, so do not point a development update at a working
DT checkout.

Use `--status` for a read-only comparison with development sources:

```sh
node tools/dt/update-types.mjs \
  --package-dir /path/to/DefinitelyTyped/types/oidc-provider \
  --status \
  /path/to/oidc-provider
```

Use `--check` to verify an exact mirror without writing. Both options also accept
`--artifact /path/to/oidc-provider-types.json` instead of a provider checkout.
The status schema remains 1; its possible reasons are `declarations`, `tests`,
and `major-version`.

Status compares all managed content after formatting it with DT's dprint and
ignores only artifact provenance. For a released artifact, declaration,
generated documentation, and test changes require a DT update, as does a new
provider major. Tooling changes alone do not require a DT update. A patch or
minor release with no content changes does not. Required updates advance DT to
`X.Y.9999`. Artifacts older than DT's tracked major/minor line are reported and
skipped. Exact `--check` additionally verifies provenance and the provider/DT
major/minor version lines.

The updater requires an explicit absolute `--package-dir` path. It validates
the exact schema, provider version, and SHA-256 hash before writing. It accepts
only the fixed managed file list and refuses symbolic links in output paths.
Existing DT declarations without the client authentication and context markers
are migrated only when each declaration can be identified exactly once;
missing, duplicate, or partial regions fail.

The updater uses only Node.js built-ins and the dprint installation from the DT
repository. It formats `index.d.ts` and copies the managed source files
byte-for-byte. Install DT's dependencies before running it.

The updater integration checks read the supplied DT package as a baseline and
apply changes only to temporary copies. To test development sources without
updating the supplied checkout:

```sh
node tools/dt/update-types.test.mjs \
  --package-dir /path/to/DefinitelyTyped/types/oidc-provider \
  /path/to/oidc-provider
```

The tests also accept `--artifact /path/to/oidc-provider-types.json` instead of
a provider checkout.
