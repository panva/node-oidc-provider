import pkg from '../../package.json' assert { type: 'json' };

export default (anchor) => `${pkg.homepage}/tree/v${pkg.version}/docs/README.md#${anchor}`;
