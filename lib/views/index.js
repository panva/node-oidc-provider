const ejs = require('ejs');

const layout = require('./layout');
const login = require('./login');
const interaction = require('./interaction');

module.exports = {
  interaction: ejs.compile(interaction),
  layout: ejs.compile(layout),
  login: ejs.compile(login),
};
