const MongoAdapter = require('./adapters/mongodb');

class HerokuExampleAdapter extends MongoAdapter {
  async upsert(_id, payload, expiresIn) {
    // HEROKU EXAMPLE ONLY, do not use the following block unless you want to drop dynamic
    //   registrations 24 hours after registration
    if (this.name === 'client') {
      expiresIn = 24 * 60 * 60 * 1000; // eslint-disable-line no-param-reassign
    }

    return super(_id, payload, expiresIn);
  }
}

module.exports = HerokuExampleAdapter;
