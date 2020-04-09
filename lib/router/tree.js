/* istanbul ignore file */
/* eslint-disable */
// https://github.com/steambap/koa-tree-router @ 0.4.4 / MIT
// Modifications:
//   - code style (npm run lint-fix)

const STATIC = 0;
const ROOT = 1;
const PARAM = 2;
const CATCH_ALL = 3;

/** @param {string} path */
function countParams(path) {
  return path.split('').filter(pc => pc === ':').length;
}

class Node {
  /**
   *
   * @param {string} path
   * @param {boolean} wildChild
   * @param {number} type
   * @param {string} indices
   * @param {Node[]} children
   * @param {function[]=} handle
   * @param {number} priority
   */
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
  /**
   *
   * @param {number} pos
   */
  addPriority(pos) {
    const children = this.children;
    children[pos].priority++;
    const prio = children[pos].priority;

    // Adjust position (move to front)
    let newPos = pos;
    while (newPos > 0 && children[newPos - 1].priority < prio) {
      const temp = children[newPos];
      children[newPos] = children[newPos - 1];
      children[newPos - 1] = temp;
      newPos--;
    }

    // Build new index char string
    if (newPos !== pos) {
      this.indices =
        this.indices.slice(0, newPos) +
        this.indices[pos] +
        this.indices.slice(newPos, pos) +
        this.indices.slice(pos + 1);
    }

    return newPos;
  }
  /**
   * Adds a node with the given handle to the path
   * @param {string} path
   * @param {function[]} handle
   */
  addRoute(path, handle) {
    let n = this;
    let fullPath = path;
    n.priority++;
    let numParams = countParams(path);

    // Non-empty tree
    if (n.path.length > 0 || n.children.length > 0) {
      walk: while (true) {
        // Find the longest common prefix
        // This also implies that the common prefix contains no ':' or '*'
        // since the existing key can't contain those chars.
        let i = 0;
        const max = Math.min(path.length, n.path.length);
        while (i < max && path[i] === n.path[i]) {
          i++;
        }

        // Split edge
        if (i < n.path.length) {
          const child = new Node(
            n.path.slice(i),
            n.wildChild,
            STATIC,
            n.indices,
            n.children,
            n.handle,
            n.priority - 1,
          );

          n.children = [child];
          n.indices = n.path[i];
          n.path = path.slice(0, i);
          n.handle = null;
          n.wildChild = false;
        }

        // Make new node a child of this node
        if (i < path.length) {
          path = path.slice(i);

          if (n.wildChild) {
            n = n.children[0];
            n.priority++;

            numParams--;

            // Check if the wildcard matches
            if (
              path.length >= n.path.length &&
              n.path === path.slice(0, n.path.length) &&
              (n.path.length >= path.length || path[n.path.length] === '/')
            ) {
              continue walk;
            } else {
              // Wildcard conflict
              let pathSeg = '';
              if (n.type === CATCH_ALL) {
                pathSeg = path;
              } else {
                pathSeg = path.split('/')[0];
              }
              const prefix =
                fullPath.slice(0, fullPath.indexOf(pathSeg)) + n.path;
              throw new Error(
                `'${pathSeg}' in new path '${fullPath}' conflicts with existing wildcard '${
                  n.path
                }' in existing prefix '${prefix}'`
              );
            }
          }

          const c = path[0];

          // Slash after param
          if (n.type === PARAM && c === '/' && n.children.length === 1) {
            n = n.children[0];
            n.priority++;
            continue walk;
          }

          // Check if a child with the next path char exists
          for (let j = 0; j < n.indices.length; j++) {
            if (c === n.indices[j]) {
              j = n.addPriority(j);
              n = n.children[j];
              continue walk;
            }
          }

          // Otherwise insert it
          if (c !== ':' && c !== '*') {
            n.indices += c;
            const child = new Node(
              '',
              false,
              STATIC
            );
            n.children.push(child);
            n.addPriority(n.indices.length - 1);
            n = child;
          }
          n.insertChild(numParams, path, fullPath, handle);
          return;
        } else if (i === path.length) {
          // Make node a (in-path leaf)
          if (n.handle !== null) {
            throw new Error(
              `A handle s already registered for path '${fullPath}'`
            );
          }
          n.handle = handle;
        }
        return;
      }
    } else {
      // Empty tree
      n.insertChild(numParams, path, fullPath, handle);
      n.type = ROOT;
    }
  }
  /**
   *
   * @param {number} numParams
   * @param {string} path
   * @param {string} fullPath
   * @param {function[]} handle
   */
  insertChild(numParams, path, fullPath, handle) {
    let n = this;
    let offset = 0; // Already handled chars of the path

    // Find prefix until first wildcard
    for (let i = 0, max = path.length; numParams > 0; i++) {
      const c = path[i];
      if (c !== ':' && c !== '*') {
        continue;
      }

      // Find wildcard end (either '/' or path end)
      let end = i + 1;
      while (end < max && path[end] !== '/') {
        if (path[end] === ':' || path[end] === '*') {
          throw new Error(
            `only one wildcard per path segment is allowed, has: '${path.slice(i)}' in path '${fullPath}'`
          );
        } else {
          end++;
        }
      }

      // Check if this Node existing children which would be unreachable
      // if we insert the wildcard here
      if (n.children.length > 0) {
        throw new Error(
          `wildcard route '${path.slice(i, end)}' conflicts with existing children in path '${fullPath}'`
        );
      }

      // check if the wildcard has a name
      if (end - i < 2) {
        throw new Error(
          `wildcards must be named with a non-empty name in path '${fullPath}'`
        );
      }

      if (c === ':') {
        // Split path at the beginning of the wildcard
        if (i > 0) {
          n.path = path.slice(offset, i);
          offset = i;
        }

        const child = new Node('', false, PARAM);
        n.children = [child];
        n.wildChild = true;
        n = child;
        n.priority++;
        numParams--;
        if (end < max) {
          n.path = path.slice(offset, end);
          offset = end;

          const staticChild = new Node(
            '',
            false,
            STATIC,
            '',
            [],
            null,
            1
          );
          n.children = [staticChild];
          n = staticChild;
        }
      } else {
        if (end !== max || numParams > 1) {
          throw new Error(
            `catch-all routes are only allowed at the end of the path in path '${fullPath}'`
          );
        }

        if (n.path.length > 0 && n.path[n.path.length - 1] === '/') {
          throw new Error(
            `catch-all conflicts with existing handle for the path segment root in path '${fullPath}'`
          );
        }

        i--;
        if (path[i] !== '/') {
          throw new Error(`no / before catch-all in path '${fullPath}'`);
        }

        n.path = path.slice(offset, i);

        // first node: catchAll node with empty path
        const catchAllChild = new Node('', true, CATCH_ALL);
        n.children = [catchAllChild];
        n.indices = path[i];
        n = catchAllChild;
        n.priority++;

        // second node: node holding the variable
        const child = new Node(
          path.slice(i),
          false,
          CATCH_ALL,
          '',
          [],
          handle,
          1
        );
        n.children = [child];

        return;
      }
    }

    // insert remaining path part and handle to the leaf
    n.path = path.slice(offset);
    n.handle = handle;
  }
  /**
   *
   * @param {string} path
   */
  search(path) {
    let handle = null;
    const params = [];
    let n = this;

    walk: while (true) {
      if (path.length > n.path.length) {
        if (path.slice(0, n.path.length) === n.path) {
          path = path.slice(n.path.length);
          // If this node does not have a wildcard child,
          // we can just look up the next child node and continue
          // to walk down the tree
          if (!n.wildChild) {
            const c = path.charCodeAt(0);
            for (let i = 0; i < n.indices.length; i++) {
              if (c === n.indices.charCodeAt(i)) {
                n = n.children[i];
                continue walk;
              }
            }

            // Nothing found.
            return { handle, params };
          }

          // Handle wildcard child
          n = n.children[0];
          switch (n.type) {
            case PARAM:
              // Find param end
              let end = 0;
              while (end < path.length && path.charCodeAt(end) !== 47) {
                end++;
              }

              // Save param value
              params.push({ key: n.path.slice(1), value: path.slice(0, end) });

              // We need to go deeper!
              if (end < path.length) {
                if (n.children.length > 0) {
                  path = path.slice(end);
                  n = n.children[0];
                  continue walk;
                }

                // ... but we can't
                return { handle, params };
              }

              handle = n.handle;

              return { handle, params };

            case CATCH_ALL:
              params.push({ key: n.path.slice(2), value: path });

              handle = n.handle;
              return { handle, params };

            default:
              throw new Error('invalid node type');
          }
        }
      } else if (path === n.path) {
        handle = n.handle;
      }

      return { handle, params };
    }
  }
}

module.exports = Node;
