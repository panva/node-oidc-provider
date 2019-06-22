# 🛑 ✋

This folder's configuration is deployed over at [op.panva.cz][heroku-example]. Every time a commit lands on master it is re-deployed and tested using [OIDC Conformance test suite][conformance-url]. It features a couple of shortcuts (read hacks), that make it possible to re-use the regular example codebase and to make sure that the dynamic clients you may register on this instance are short-lived. Hop over to the regular example folder or step by step repo for inspiration, not here ;)

If you can follow the code tho, by all means, try it. Just copy pasting this though, I wouldn't
recommend it without understanding it first.

[heroku-example]: https://op.panva.cz/.well-known/openid-configuration
[conformance-url]: https://github.com/panva/oidc-provider-conformance-tests
