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
event overloads, interaction policy, and public error declarations. The grant
helper declaration under `lib/` is copied byte-for-byte.

Run the documentation generator after changing these files:

```sh
node docs/update-configuration.js
node docs/update-configuration.js --check
node docs/update-configuration.js --types-json
```

The last command emits the versioned, hashed artifact consumed by
`@types/oidc-provider`'s `scripts/update-types.mjs` mirror.
