import Debug from 'debug';

if (!('DEBUG' in process.env)) {
  process.env.DEBUG = 'runner';
}

export default new Debug('runner');
