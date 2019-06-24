const instance = require('./weak_cache');

function addClient(properties) {
  instance(this).clientAddStatic(properties);
}

module.exports = function initializeClients(clients = []) {
  clients.map(addClient, this);
};
