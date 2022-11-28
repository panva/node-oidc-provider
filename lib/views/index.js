const ejs = require('ejs');

const layout = require('./layout.js');
const login = require('./login.js');
const interaction = require('./interaction.js');

module.exports = {
  interaction: ejs.compile(interaction),
  layout: ejs.compile(layout),
  login: ejs.compile(login),
};
