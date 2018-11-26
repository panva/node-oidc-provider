const instance = require('./weak_cache');

function addClient(client) {
  return instance(this).clientAdd(client, undefined, Infinity).then((addedClient) => {
    Object.defineProperty(addedClient, 'noManage', { value: true });
    return addedClient;
  });
}

module.exports = async function initializeClients(clients = []) {
  await instance(this).clientClear();
  return Promise.all(clients.map(addClient, this));
};
