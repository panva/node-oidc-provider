const instance = require('./weak_cache');

function addClient(client) {
  return instance(this).clientAdd(client).then((addedClient) => {
    Object.defineProperty(addedClient, 'noManage', { value: true });
    return addedClient;
  });
}

module.exports = function initializeClients(clientsConf) {
  const clients = (() => {
    if (typeof clientsConf === 'undefined') {
      return [];
    }
    return clientsConf;
  })();
  return Promise.all(clients.map(addClient.bind(this)));
};
