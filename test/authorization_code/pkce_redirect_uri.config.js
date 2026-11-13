import getConfig from '../default.config.js';

const config = getConfig();
config.allowOmittingSingleRegisteredRedirectUri = false;
config.pkce = { required: () => false };

export default {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code'],
    grant_types: ['authorization_code'],
    redirect_uris: ['https://client.example.com/cb', 'https://client.example.com/other'],
  }, {
    client_id: 'single',
    client_secret: 'secret',
    response_types: ['code'],
    grant_types: ['authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'native',
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    response_types: ['code'],
    grant_types: ['authorization_code'],
    redirect_uris: ['http://127.0.0.1/cb'],
  }],
};
