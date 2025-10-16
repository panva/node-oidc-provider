import debug from 'debug';

if (!('DEBUG' in process.env)) {
  process.env.DEBUG = 'runner';
}

export default debug('runner');
