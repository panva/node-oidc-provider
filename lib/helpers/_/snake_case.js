module.exports = (str = '') => str.replace(/([A-Z][a-z])/g, (x) => `_${x}`.toLowerCase()).replace(/^_+/, '');
