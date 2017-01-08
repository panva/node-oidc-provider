'use strict';

const Provider = require('../lib');
const express = require('express'); // eslint-disable-line import/no-unresolved

const app = express();

const provider = new Provider('http://localhost:3000/op');

provider.initialize().then(() => {
  app.use('/op', provider.callback);
  app.listen(3000);
});
