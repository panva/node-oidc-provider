import instance from './weak_cache.js';

function addClient(properties) {
  instance(this).clientAddStatic(properties);
}

export default function initializeClients(clients = []) {
  clients.map(addClient, this);
}
