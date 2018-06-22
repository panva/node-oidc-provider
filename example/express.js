// You should read the Koa corresponding example (index.js in this directory) to
// learn about many possible options.

const express = require('express'); // eslint-disable-line import/no-unresolved

const Provider = require('../lib');

const app = express();

const provider = new Provider('http://localhost:3000/op', {
  formats: { default: 'opaque' },
});

provider.initialize().then(() => {
  app.use('/op', provider.callback);
  app.listen(3000);
});
