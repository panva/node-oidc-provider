# Contributing to oidc-provider

Please note we have a [code of conduct][coc], please follow it in all your interactions with the
project.

When contributing to this project, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this project before proposing a change via a Pull
Request. Use (and follow!) the appropriate [Issue Template][new-issue] to do so. The project
promotes and follows current best practices in regards to the specifications it implements.
A contribution that tries to implement something non-standard will most likely be dismissed.

## Rules of the discussions

Remember to be very clear and transparent when discussing any issue in the discussions boards. We
ask that you keep the language to English and keep on track with the issue at hand. Lastly, please
be respectful of our fellow contributors and keep an exemplary level of professionalism at all
times.

## Pull Request Checklist

- Follow the eslint rules
- Do not modify the eslint rules
- File names must be snake_case.js
- Add tests covering 100% of the library code you are adding or modifying
- Unless previously agreed upon (i.e. fixing a bug) all contributions must be backwards compatible
- Follow [standard-version][standard-version] commit guidelines
- _[When updating defaults.js]_
  - Follow the block comment convention
  - Run `node ./docs/update-configuration.js` and include the resulting updates in your PR
- _[When updating configuration.md]_
  - Do not edit or update the `## Configuration options` section, it's generated from inline
    comments of defaults.js

[coc]: https://github.com/panva/node-oidc-provider/blob/master/CODE_OF_CONDUCT.md
[new-issue]: https://github.com/panva/node-oidc-provider/issues/new/choose
[standard-version]: https://github.com/conventional-changelog/standard-version
