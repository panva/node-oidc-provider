# oidc-provider declaration and test mirror

The provider owns the release synchronization tools in `tools/dt`, the declaration
sources in `types`, and the generated configuration contracts. The schema 2
artifact includes the client authentication methods and complete `OIDCContext`
declaration, the grant helper declarations, the DT test suite, and these tools.
Do not edit their generated DT regions or mirrored files by hand.

Generate and apply the complete artifact from a provider checkout:

```sh
node tools/dt/update-types.mjs \
  --package-dir /path/to/DefinitelyTyped/types/oidc-provider \
  /path/to/oidc-provider
```

Alternatively, consume a release artifact without provider source:

```sh
node update-types.mjs \
  --package-dir /path/to/DefinitelyTyped/types/oidc-provider \
  --artifact /path/to/oidc-provider-types.json
```

The mirrored `scripts/update-types.mjs` infers its DT package directory, so its
`--package-dir` option is optional. Portable copies require the explicit absolute
path. The updater validates the exact schema, provider version, and SHA-256 hash
before writing. It accepts only the fixed managed file list and refuses
symbolic links in output paths. Existing DT declarations without the client
authentication and context markers are migrated only when each declaration can
be identified exactly once; missing, duplicate, or partial regions fail.

Use `--check` to verify the exact mirror without writing, or `--status` to produce
deterministic JSON describing a potential DT update. Both accept either source
form above. The status schema remains 1; its possible reasons are `declarations`,
`tests` (including synchronization tooling), and `major-version`.

Status compares all managed content after formatting it with DT's dprint and
ignores only artifact provenance. Declaration, generated documentation, test,
and tooling changes require an update, as does a new provider major. A patch or
minor release with no content changes does not. Required updates advance DT to
`X.Y.9999`. Artifacts older than DT's tracked major/minor line are reported and
skipped. Exact `--check` additionally verifies provenance and the provider/DT
major/minor version lines.

The updater uses only Node.js built-ins and the dprint installation from the DT
repository. It formats `index.d.ts` and copies the managed source files
byte-for-byte. Install DT's dependencies before running it. The integration
checks accept the same source options:

```sh
node update-types.test.mjs \
  --package-dir /path/to/DefinitelyTyped/types/oidc-provider \
  --artifact /path/to/oidc-provider-types.json
```

## Release synchronization

Download the complete artifact named `oidc-provider-types-vX.Y.Z` from the
provider's release workflow. It contains exactly `oidc-provider-types.json`,
`update-types.mjs`, `update-types.test.mjs`, `sync-release.mjs`,
`sync-release.test.mjs`, and `README.md`. Run its portable helper against your DT
checkout so it can upgrade the older scripts in upstream DT:

```sh
node /path/to/bundle/sync-release.mjs \
  --repository /path/to/DefinitelyTyped \
  --tag v9.13.0 \
  --artifact /path/to/bundle/oidc-provider-types.json
```

The helper also accepts `--run-id 123456789` instead of `--artifact` to download
the exact named artifact from `panva/node-oidc-provider`. Downloads must contain
the JSON alone or the complete flat tooling bundle; extra files, directories,
and symlinks are rejected. The mirrored `scripts/sync-release.mjs` infers its DT
repository; portable copies require `--repository`.

Before changing anything, synchronization verifies GitHub CLI authentication,
the `origin` fork and official `upstream` remote, Git author identity, Node.js,
and pnpm. The authenticated GitHub user must own `origin`.

The helper fetches `upstream/master`, creates a temporary Git worktree, installs
only the root tooling and `@types/oidc-provider` dependency closure with a
no-lockfile workspace install, and checks whether the release needs an update.
It always invokes its companion updater and tests, including before the DT
worktree has upgraded its scripts. A required update runs:

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

Pass `--submit` to push without force and open the deterministic PR against
`DefinitelyTyped/DefinitelyTyped:master`. Existing open or merged PRs for the
release branch are successful no-ops. Closed, unmerged PRs and remote branches
without a PR require manual recovery. A matching prepared local branch can be
reused safely.

Temporary state is preserved on failure. Pass `--keep-temp` to preserve it after
success as well. Run the focused orchestration tests separately with:

```sh
node --test /path/to/bundle/sync-release.test.mjs
```
