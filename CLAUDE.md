This is a fork of panva's node-oidc-provider (upstream [here](https://github.com/panva/node-oidc-provider), Civic's fork [here](https://github.com/civicteam/node-oidc-provider)).

This fork is used as the basis of the Auth Server in Civic's Auth product. The Civic-specific changes (reasons for forking) can be found in CIVIC_CHANGES.md.

When maintaining and making changes to this fork, our goals are as follows:
1. Regularly sync from upstream to get the latest security updates and new features, so that our fork does not fall behind
2. Any change must clearly be documented in CIVIC_CHANGES.md, most importantly describing *why* the change was needed, and what the trade-offs are (e.g. cookieless support for iframes trades off against 100% session authenticity verification).
3. We have to clearly understand how our changes impact adherance to the relevant OAuth and OIDC specs, and where we deviate, we must be sure it's documented and justified.
4. Ensure that there are tests for all changes.