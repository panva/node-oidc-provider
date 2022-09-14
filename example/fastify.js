const Fastify = require('fastify');
const fastifyExpress = require('@fastify/express');

const { Provider } = require('../lib');

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;
const configuration = require('./support/configuration');

async function build() {
  const fastify = Fastify();
  await fastify.register(fastifyExpress);

  const oidc = new Provider(ISSUER, configuration);

  fastify.use('/oidc', oidc.callback());
  return fastify;
}

build()
  .then((fastify) => fastify.listen({ port: PORT }))
  .catch((err) => console.error(err));
