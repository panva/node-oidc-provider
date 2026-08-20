export default (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
