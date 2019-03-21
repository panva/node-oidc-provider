const instance = require('./weak_cache');

async function addClient(properties) {
  const client = await instance(this).clientAdd(properties, { static: true });
  Object.defineProperty(client, 'noManage', { value: true });
}

module.exports = async function initializeClients(clients = []) {
  await Promise.all(clients.map(addClient, this));
};
