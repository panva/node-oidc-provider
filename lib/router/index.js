// https://github.com/steambap/koa-tree-router @ 0.7.0 / MIT
// Modifications:
//   - code style
//   - compose middlewares upfronts rather then composing on every request
//   - removed 405 handling
//   - removed unused methods

const compose = require('koa-compose');

const Node = require('./tree');

const NOT_FOUND = { handle: null, params: [] };

class Router {
  constructor(opts = {}) {
    this.trees = {};
    this.opts = opts;
  }

  on(method, path, ...handle) {
    if (!this.trees[method]) {
      this.trees[method] = new Node();
    }
    this.trees[method].addRoute(path, compose(handle));
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
    const router = this;
    return (ctx, next) => {
      const { handle, params } = router.find(ctx.method, ctx.path);
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
