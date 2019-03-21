const nanoid = require('nanoid/generate');

// base64url charset
const CHARSET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-';

module.exports = (length = 21, charset = CHARSET) => nanoid(charset, length);
