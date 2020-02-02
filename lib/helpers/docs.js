const { homepage, version } = require('../../package.json');

module.exports = (anchor) => `${homepage}/tree/v${version}/docs/README.md#${anchor}`;
