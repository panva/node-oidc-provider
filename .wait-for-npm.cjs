const { name } = require('./package.json')

const MAX_WAIT = 60 * 60_000
const RETRY_INTERVAL = 60_000
const REQUEST_TIMEOUT = 15_000

async function isPublished(version) {
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
    {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    },
  )

  if (response.status === 404) {
    return false
  }
  if (!response.ok) {
    throw new Error(`npm registry returned ${response.status} ${response.statusText}`)
  }

  const manifest = await response.json()
  return manifest.version === version
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// `npm stage publish` only stages: the version stays unavailable until it is
// approved. Holding the publishing job here gates everything that depends on
// it - the branch pushes and the release the tarball is attached to - so none
// of it advertises a version nobody can install yet.
async function main() {
  // GITHUB_REF_NAME is the tag that triggered the run; `git tag --points-at
  // HEAD` returns every tag on the commit, newline separated
  const { GITHUB_REF_NAME } = process.env
  if (!GITHUB_REF_NAME) {
    throw new Error('GITHUB_REF_NAME is not set')
  }
  const version = GITHUB_REF_NAME.replace(/^v/, '')
  const deadline = Date.now() + MAX_WAIT

  for (;;) {
    // a timeout, a 429 or a 5xx is a reason to poll again, not to fail the
    // release - the deadline below is what bounds this
    let reason = 'is not published yet'
    try {
      if (await isPublished(version)) {
        console.log(`${name}@${version} is available on npm`)
        return
      }
    } catch (err) {
      reason = `could not be checked: ${err.message}`
    }

    if (Date.now() >= deadline) {
      throw new Error(`${name}@${version} was not published within ${MAX_WAIT / 60_000} minutes`)
    }

    console.log(`${name}@${version} ${reason}, retrying`)
    await wait(RETRY_INTERVAL)
  }
}

module.exports = { isPublished }

if (require.main === module) {
  main()
}
