/* eslint-disable no-console, no-await-in-loop, no-loop-func */

const got = require('got');

const {
  TRAVIS_BUILD_NUMBER,
  TRAVIS_COMMIT,
  TRAVIS_REPO_SLUG,
  TRAVIS_AUTH_TOKEN,
} = process.env;

const slug = encodeURIComponent('panva/oidc-provider-conformance-tests');

(async () => {
  const { body: { request: { id } } } = await got.post(`https://api.travis-ci.com/repo/${slug}/requests`, {
    headers: {
      'Travis-API-Version': 3,
      Authorization: `token ${TRAVIS_AUTH_TOKEN}`,
    },
    json: true,
    body: {
      request: {
        message: `Triggered by upstream build #${TRAVIS_BUILD_NUMBER} of ${TRAVIS_REPO_SLUG} commit ${TRAVIS_COMMIT}`,
        branch: 'master',
      },
    },
  });

  console.log('triggered request id', id);

  let final;
  while (!final) {
    await got.get(`https://api.travis-ci.com/repo/${slug}/request/${id}`, {
      headers: {
        'Travis-API-Version': 3,
        Authorization: `token ${TRAVIS_AUTH_TOKEN}`,
      },
      json: true,
    }).then(({ body }) => {
      if (!body.builds.length) {
        return new Promise((resolve) => { setTimeout(resolve, 20 * 1000); });
      }
      switch (body.builds[0].state) {
        case 'started':
          console.log(`${new Date().toString()}:`, 'build is running');
          return new Promise((resolve) => { setTimeout(resolve, 20 * 1000); });
        case 'created':
          console.log(`${new Date().toString()}:`, 'build is pending execution');
          return new Promise((resolve) => { setTimeout(resolve, 20 * 1000); });
        default:
          final = body.builds[0].state;
          return undefined;
      }
    });
  }

  if (final !== 'passed') {
    throw new Error(`triggered build status: ${final}`);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
