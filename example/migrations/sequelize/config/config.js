module.exports = {
  development: {
    username: process.env.dbUser,
    password: process.env.dbPass,
    database: process.env.dbName,
    host: process.env.dbHost,
    port: 5432,
    dialect: 'postgres',
    migrationStorageTableName: 'SequelizeMeta',
  },
  test: {
    username: '',
    password: '',
    database: '',
    host: '',
    dialect: 'postgres',
  },
  production: {
    username: '',
    password: '',
    database: '',
    host: '',
    dialect: 'postgres',
  },
};
