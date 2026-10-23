# Extensibility declaration sources

These source-only templates are the canonical TypeScript contracts for the
provider's high-drift extensibility surface. They are not included in the npm
package; DefinitelyTyped remains the declaration publisher.

`configuration.d.ts` owns configuration, feature, Account, Adapter,
ResourceServer, and external-signing contracts. Its `@configuration-path`
annotations must have one-to-one coverage with the option blocks beside the
runtime defaults. `@configuration-docs` repeats the generated documentation on
a related type refinement without declaring a second contract, and
`@configuration-dynamic` identifies namespaces whose child keys are
application-defined.

`provider.d.ts`, `events.js`, and `related.d.ts` own Provider extension methods,
event overloads, interaction policy, and public error declarations.
`client-auth.d.ts` owns the supported client authentication method union, and
`oidc-context.d.ts` owns the OIDC request context contract. Their generated
regions are updated together with configuration so that related runtime
changes reach DefinitelyTyped in the same release. The grant helper
declaration under `lib/` is copied byte-for-byte.

`oidc-provider-tests.ts` is the canonical DefinitelyTyped test suite. It is
copied in full by the release sync alongside the declarations, including
configuration constraints and examples for experimental grant helpers.
Change declaration templates and tests here; do not edit their generated
regions or the mirrored test file directly in DefinitelyTyped. The sources
and tests in this directory are not published in the npm package.

Run the documentation generator after changing these files:

```sh
node docs/update-configuration.js
node docs/update-configuration.js --check
node docs/update-configuration.js --types-json
```

The last command emits the versioned, hashed declaration and test artifact
consumed by `tools/dt/update-types.mjs` or its copy in the downloaded release
bundle. Synchronization tooling stays in provider and the bundle; it is not
copied into DefinitelyTyped.
