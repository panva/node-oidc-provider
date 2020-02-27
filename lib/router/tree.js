/* eslint-disable no-param-reassign, no-continue, no-constant-condition, no-labels,
   no-restricted-syntax */
// https://github.com/steambap/koa-tree-router @ 0.5.0 / MIT
// Modifications:
//   - code style (npm run lint-fix)
//   - strip down

const STATIC = 0;
const ROOT = 1;
const PARAM = 2;

class Node {
  constructor(
    path = '',
    wildChild = false,
    type = STATIC,
    indices = '',
    children = [],
    handle = null,
    priority = 0,
  ) {
    this.path = path;
    this.wildChild = wildChild;
    this.type = type;
    this.indices = indices;
    this.children = children;
    this.handle = handle;
    this.priority = priority;
  }

  addPriority(pos) {
    const { children } = this;
    children[pos].priority += 1;
    const prio = children[pos].priority;

    let newPos = pos;
    while (newPos > 0 && children[newPos - 1].priority < prio) {
      const temp = children[newPos];
      children[newPos] = children[newPos - 1];
      children[newPos - 1] = temp;
      newPos -= 1;
    }

    if (newPos !== pos) {
      this.indices = this.indices.slice(0, newPos)
        + this.indices[pos]
        + this.indices.slice(newPos, pos)
        + this.indices.slice(pos + 1);
    }

    return newPos;
  }

  addRoute(path, handle) {
    let n = this;
    const fullPath = path;
    n.priority += 1;
    let numParams = path.split('').filter((pc) => pc === ':').length;

    if (n.path.length > 0 || n.children.length > 0) {
      walk: while (true) {
        let i = 0;
        const max = Math.min(path.length, n.path.length);
        while (i < max && path[i] === n.path[i]) {
          i += 1;
        }

        if (i < n.path.length) {
          const child = new Node(
            n.path.slice(i), n.wildChild, STATIC, n.indices, n.children, n.handle, n.priority - 1,
          );

          n.children = [child];
          n.indices = n.path[i];
          n.path = path.slice(0, i);
          n.handle = null;
          n.wildChild = false;
        }

        if (i < path.length) {
          path = path.slice(i);

          if (n.wildChild) {
            [n] = n.children;
            n.priority += 1;

            numParams -= 1;
            continue;
          }

          const c = path[0];

          for (let j = 0; j < n.indices.length; j += 1) {
            if (c === n.indices[j]) {
              j = n.addPriority(j);
              n = n.children[j];
              continue walk;
            }
          }

          n.indices += c;
          const child = new Node('', false, STATIC);
          n.children.push(child);
          n.addPriority(n.indices.length - 1);
          n = child;
          n.insertChild(numParams, path, fullPath, handle);
          return;
        }

        n.handle = handle;
        return;
      }
    } else {
      n.insertChild(numParams, path, fullPath, handle);
      n.type = ROOT;
    }
  }

  insertChild(numParams, path, fullPath, handle) {
    let n = this;
    let offset = 0;

    for (let i = 0, max = path.length; numParams > 0; i += 1) {
      const c = path[i];
      if (c !== ':') {
        continue;
      }

      let end = i + 1;
      while (end < max && path[end] !== '/') {
        end += 1;
      }

      n.path = path.slice(offset, i);
      offset = i;

      const child = new Node('', false, PARAM);
      n.children = [child];
      n.wildChild = true;
      n = child;
      n.priority += 1;
      numParams -= 1;
      if (end < max) {
        n.path = path.slice(offset, end);
        offset = end;

        const staticChild = new Node('', false, STATIC, '', [], null, 1);
        n.children = [staticChild];
        n = staticChild;
      }
    }

    n.path = path.slice(offset);
    n.handle = handle;
  }

  search(path) {
    let handle = null;
    const params = [];
    let n = this;

    walk: while (true) {
      if (path.length > n.path.length) {
        path = path.slice(n.path.length);
        if (!n.wildChild) {
          const c = path.charCodeAt(0);
          for (let i = 0; i < n.indices.length; i += 1) {
            if (c === n.indices.charCodeAt(i)) {
              n = n.children[i];
              continue walk;
            }
          }

          return { handle, params };
        }

        [n] = n.children;

        let end = 0;
        while (end < path.length && path.charCodeAt(end) !== 47) {
          end += 1;
        }

        params.push({ key: n.path.slice(1), value: path.slice(0, end) });

        if (end < path.length) {
          path = path.slice(end);
          [n] = n.children;
          continue;
        }

        handle = n.handle;
        return { handle, params };
      }

      handle = n.handle;

      return { handle, params };
    }
  }
}

module.exports = Node;
