/* eslint-disable */
// https://github.com/steambap/koa-tree-router @ 0.7.0 / MIT
// Modifications:
//   - code style
//   - compose middlewares upfront rather then composing on every request
//   - removed 405 handling
//   - removed unused methods

const STATIC = 0;
const ROOT = 1;
const PARAM = 2;
const CATCH_ALL = 3;

/**
 * Search for a wildcard segment and check the name for invalid characters.
 * Returns -1 as index, if no wildcard was found
 * @param {string} path
 */
function findWildcard(path) {
  for (let i = 0; i < path.length; i++) {
    const c = path[i];
    if (c !== ":" && c !== "*") {
      continue;
    }

    let valid = true;
    const remaining = path.slice(i + 1);
    for (let end = 0; end < remaining.length; end++) {
      const char = remaining[end];
      if (char === "/") {
        return {
          wildcard: path.slice(i, i + 1 + end),
          i,
          valid
        };
      }
      if (char === ":" || char === "*") {
        valid = false;
      }
    }

    return {
      wildcard: path.slice(i),
      i,
      valid
    };
  }

  return {
    wildcard: "",
    i: -1,
    valid: false
  };
}

/**
 * @param {string} a
 * @param {string} b
 */
function longestCommonPrefix(a, b) {
  let i = 0;
  const max = Math.min(a.length, b.length);
  while (i < max && a[i] === b[i]) {
    i++;
  }

  return i;
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
    path = "",
    wildChild = false,
    type = STATIC,
    indices = "",
    children = [],
    handle = null,
    priority = 0
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

    // Adjust position (move to fron)
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

    if (n.path.length === 0 && n.children.length === 0) {
      n.insertChild(path, fullPath, handle);
      n.type = ROOT;
      return;
    }

    walk: while (true) {
      // Find the longest common prefix
      // This also implies that the common prefix contains no ':' or '*'
      // since the existing key can't contain those chars.
      let i = longestCommonPrefix(path, n.path);

      // Split edge
      if (i < n.path.length) {
        const child = new Node(
          n.path.slice(i),
          n.wildChild,
          STATIC,
          n.indices,
          n.children,
          n.handle,
          n.priority - 1
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

          // Check if the wildcard matches
          if (
            path.length >= n.path.length &&
            n.path === path.slice(0, n.path.length) &&
            // Adding a child to a catchAll is not possible
            n.type !== CATCH_ALL &&
            (n.path.length >= path.length || path[n.path.length] === "/")
          ) {
            continue walk;
          } else {
            // Wildcard conflict
            let pathSeg = path;
            if (n.type !== CATCH_ALL) {
              pathSeg = path.split("/")[0];
            }
            const prefix =
              fullPath.slice(0, fullPath.indexOf(pathSeg)) + n.path;
            throw new Error(
              `'${pathSeg}' in new path '${fullPath}' conflicts with existing wildcard '${n.path}' in existing prefix '${prefix}'`
            );
          }
        }

        const c = path[0];

        // Slash after param
        if (n.type === PARAM && c === "/" && n.children.length === 1) {
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
        if (c !== ":" && c !== "*") {
          n.indices += c;
          const child = new Node("", false, STATIC);
          n.children.push(child);
          n.addPriority(n.indices.length - 1);
          n = child;
        }
        n.insertChild(path, fullPath, handle);
        return;
      }

      if (n.handle !== null) {
        throw new Error(
          "A handle is already registered for path '" + fullPath + "'"
        );
      }
      n.handle = handle;
      return;
    }
  }
  /**
   *
   * @param {string} path
   * @param {string} fullPath
   * @param {function[]} handle
   */
  insertChild(path, fullPath, handle) {
    let n = this;

    while (true) {
      // Find prefix until first wildcard
      let { wildcard, i, valid } = findWildcard(path);
      if (i < 0) {
        break;
      }

      if (!valid) {
        throw new Error(
          "only one wildcard per path segment is allowed, has: '" +
            wildcard +
            "' in path '" +
            fullPath +
            "'"
        );
      }

      if (wildcard.length < 2) {
        throw new Error(
          "wildcards must be named with a non-empty name in path '" +
            fullPath +
            "'"
        );
      }

      if (n.children.length > 0) {
        throw new Error(
          "wildcard route '" +
            wildcard +
            "' conflicts with existing children in path '" +
            fullPath +
            "'"
        );
      }

      if (wildcard[0] === ":") {
        // param
        if (i > 0) {
          // Insert prefix before the current wildcard
          n.path = path.slice(0, i);
          path = path.slice(i);
        }

        n.wildChild = true;
        const child = new Node(wildcard, false, PARAM);
        n.children = [child];
        n = child;
        n.priority++;

        if (wildcard.length < path.length) {
          path = path.slice(wildcard.length);

          const staticChild = new Node("", false, STATIC, "", [], null, 1);
          n.children = [staticChild];
          n = staticChild;
          continue;
        }

        // Otherwise we're done. Insert the handle in the new leaf
        n.handle = handle;
        return;
      } else {
        // catchAll
        if (i + wildcard.length != path.length) {
          throw new Error(
            "catch-all routes are only allowed at the end of the path in path '" +
              fullPath +
              "'"
          );
        }

        if (n.path.length > 0 && n.path[n.path.length - 1] === "/") {
          throw new Error(
            "catch-all conflicts with existing handle for the path segment root in path '" +
              fullPath +
              "'"
          );
        }

        // Currently fixed width 1 for '/
        i--;
        if (path[i] !== "/") {
          throw new Error("no / before catch-all in path '" + fullPath + "'");
        }

        n.path = path.slice(0, i);

        // First node: catchAll node with empty path
        const catchAllChild = new Node("", true, CATCH_ALL);
        n.children = [catchAllChild];
        n.indices = "/";
        n = catchAllChild;
        n.priority++;

        // Second node: node holding the variable
        const child = new Node(
          path.slice(i),
          false,
          CATCH_ALL,
          "",
          [],
          handle,
          1
        );
        n.children = [child];

        return;
      }
    }

    // Insert remaining path part and handle to the leaf
    n.path = path;
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
              throw new Error("invalid node type");
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
