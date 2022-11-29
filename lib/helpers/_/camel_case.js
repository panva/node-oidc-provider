export default (str = '') => str.replace(/(_\w)/g, (x) => x.replace('_', '').toUpperCase());
