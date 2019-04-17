const instance = require('./weak_cache');

function addClient(properties) {
  const client = instance(this).clientAddStatic(properties);
  Object.defineProperty(client, 'noManage', { value: true });
}

module.exports = function initializeClients(clients = []) {
  clients.map(addClient, this);
};
