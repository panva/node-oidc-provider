const instance = require('./weak_cache');

function addClient(client) {
  return instance(this).clientAdd(client).then((addedClient) => {
    Object.defineProperty(addedClient, 'noManage', { value: true });
    return addedClient;
  });
}

module.exports = function initializeClients(clients = []) {
  return Promise.all(clients.map(addClient, this));
};
