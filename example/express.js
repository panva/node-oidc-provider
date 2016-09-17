'use strict';

const Provider = require('../lib').Provider;
const express = require('express'); // eslint-disable-line import/no-unresolved

const app = express();

app.use('/op', new Provider('http://localhost:3000/op').app.callback());

app.listen(3000);
