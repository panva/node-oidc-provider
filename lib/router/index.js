/* istanbul ignore file */
// https://github.com/steambap/koa-tree-router @ 0.4.4 / MIT
// Modifications:
//   - code style (npm run lint-fix)
//   - fixed composed middleware rather then composing on every request
//   - removed 405 handling

const compose = require('koa-compose');

const Node = require('./tree');

const NOT_FOUND = { handle: null, params: [] };

class Router {
  constructor(opts = {}) {
    this.trees = {};
    this.opts = opts;
  }

  on(method, path, ...middlewares) {
    if (!this.trees[method]) {
      this.trees[method] = new Node();
    }
    this.trees[method].addRoute(path, compose(middlewares));
    return this;
  }

  get(...arg) {
    return this.on('GET', ...arg);
  }

  put(...arg) {
    return this.on('PUT', ...arg);
  }

  post(...arg) {
    return this.on('POST', ...arg);
  }

  delete(...arg) {
    return this.on('DELETE', ...arg);
  }

  options(...arg) {
    return this.on('OPTIONS', ...arg);
  }

  find(method, path) {
    const tree = this.trees[method];
    if (tree) {
      return tree.search(path);
    }
    return NOT_FOUND;
  }

  routes() {
    return (ctx, next) => {
      const { handle, params } = this.find(ctx.method, ctx.path);

      if (!handle) {
        return next();
      }

      ctx.params = {};
      params.forEach(({ key, value }) => {
        ctx.params[key] = value;
      });

      return handle(ctx, next);
    };
  }
}

module.exports = Router;
