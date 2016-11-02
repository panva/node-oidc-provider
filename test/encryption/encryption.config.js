'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { request: true, encryption: true };

const privKey = { keys: [{ kty: 'RSA',
  kid: 'c0jtckfxSkYmeFpVA_YWYdhxLl7C5ZPtjUe6l3-eyxg',
  e: 'AQAB',
  n: 'zvd7qgr1knpZHfNB4NLAjdN0dOUI6-SzQNXbh30nY0rXKhoamrHSmAzNS8FintDhjFUVM_fZPZ9IkpBvFmAyAnJa9AOxoNeku_Z1Tnfflev1SekDSD52whl-q5GvfqhQaSkrXdNdaWqGrndU1eVc7FOzG_4LLLV8mbl_bmxl1AM',
  d: 'KQT52IjVhROEqB_3VZTPnwxiz2w5aW9pa5c3LFJMxSwnGuwTi8dkosgexD3uyuVBXqvaSPN9de4k1w-TRM8J-gCHycmNBmuyMpHftr0BK795VMuO5zL477ldZd6Qiv4CPgfkEwEqHDUU6SX81HH__ob1d-y-w2yNFoBInS0JWVk',
  p: '_IiW6u1nMcC_mBGIsQ_WaUochJGlGkR7Fwl3uiqGzw0rI_VKhY25vQhX5gJwoCq6HYdIC9Wln1EdTLm0K_brFQ',
  q: '0c7FNm6mOvUHYnbCjMU1aqRQM1rRrUAANYBumFgPY9oD5VwEa0EVm9oFErEq5UiTPWeMZfdSooHordRXsaaotw',
  dp: 'uILkIcpLt-JpGqbVBOnZcxyfMY1o4IRgmzhjrjYcQXQRrTgvtt0SdLd_4aKuv5f4XFLXpS340SrnCYQ1zFmg8Q',
  dq: 'IqKy1diQYp0-udeHKHwJ5G_5uXCduq8dGbf5CfdHmyFLkVqOdDJLYe4s9jf_L9i6TeHBQLgCkUdG5SNv0qkDow',
  qi: 'pfgMN7EtYsM2mW7hBSZReCO3rQs91ayQkgZRhiWrM61zoBvjXeuRw6t-Sa8vjqFtStQXbvaIghdtKOBOz_2zZg' }] };

const pubKey = { keys: [{ kty: 'RSA',
  kid: 'c0jtckfxSkYmeFpVA_YWYdhxLl7C5ZPtjUe6l3-eyxg',
  e: 'AQAB',
  n: 'zvd7qgr1knpZHfNB4NLAjdN0dOUI6-SzQNXbh30nY0rXKhoamrHSmAzNS8FintDhjFUVM_fZPZ9IkpBvFmAyAnJa9AOxoNeku_Z1Tnfflev1SekDSD52whl-q5GvfqhQaSkrXdNdaWqGrndU1eVc7FOzG_4LLLV8mbl_bmxl1AM' }] };

module.exports = {
  config,
  privKey,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token token', 'code'],
      grant_types: ['implicit', 'authorization_code'],
      jwks: pubKey,
      id_token_encrypted_response_alg: 'RSA1_5',
      // id_token_encrypted_response_enc: 'A128CBC-HS256',
      request_object_encryption_alg: 'RSA1_5',
      // request_object_encryption_enc: 'A128CBC-HS256',
      userinfo_encrypted_response_alg: 'RSA1_5',
      // userinfo_encrypted_response_enc: 'A128CBC-HS256',
    },
    {
      client_id: 'clientSymmetric',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      id_token_encrypted_response_alg: 'PBES2-HS384+A192KW',
    }
  ]
};
