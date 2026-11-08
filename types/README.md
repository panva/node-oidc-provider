# Declaration sources

This directory owns every declaration and TypeScript test handed over to
DefinitelyTyped. These source-only templates are not included in the npm
package; DefinitelyTyped remains the declaration publisher.

`index.d.ts` is the complete declaration template. It owns imports, exports,
shared algorithm unions, JWK/JWKS and client metadata types, model declarations,
and the core Provider declaration. Its five `@generate` directives insert the
contracts assembled from the other canonical sources:

- `configuration.d.ts` owns configuration, feature, Account, Adapter,
  ResourceServer, and external-signing contracts. Its `@configuration-path`
  annotations must have one-to-one coverage with the option blocks beside the
  runtime defaults. `@configuration-docs` repeats generated documentation on a
  related type refinement without declaring a second contract, and
  `@configuration-dynamic` identifies namespaces whose child keys are
  application-defined.
- `provider.d.ts` and `events.js` own Provider extension methods and event
  overloads.
- `related.d.ts` owns interaction policy and public error declarations.
- `client-auth.d.ts` owns the supported client authentication method union.
- `oidc-context.d.ts` owns the OIDC request context contract.

The generator validates the assembled `index.d.ts` and includes the complete
file in the release artifact. The grant helper declaration under `lib/` and
`oidc-provider-tests.ts`, the canonical DT test suite, are included byte-for-byte.
There are no declaration regions maintained separately in DT.

Edit declaration sources and tests here alongside the provider change.
DefinitelyTyped synchronization happens after release as a separate task using
the released tag's handoff bundle. Do not update or commit a sibling
DefinitelyTyped checkout during provider development. See the
[release synchronization flow](../tools/dt/README.md).

Run the documentation generator after changing these files:

```sh
node docs/update-configuration.js
node docs/update-configuration.js --check
node docs/update-configuration.js --types-json
```

The last command emits the versioned, hashed artifact containing the complete
`index.d.ts`, grant helper declarations, and tests consumed by
`tools/dt/update-types.mjs` or its copy in the downloaded release bundle.
Synchronization tooling stays in provider and the bundle; it is not copied
into DefinitelyTyped. DT package metadata and its compiler/publishing
configuration remain in DT; the updater manages the package version.
