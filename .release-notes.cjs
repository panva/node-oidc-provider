const fs = require('node:fs')
const { execFileSync } = require('node:child_process')

function extractReleaseNotes(changelog, version) {
  const releaseHeading = `## [${version}]`
  const releaseStart = changelog.indexOf(releaseHeading)

  if (releaseStart === -1) {
    throw new Error(`could not find ${releaseHeading} in CHANGELOG.md`)
  }

  const notesStart = changelog.indexOf('\n', releaseStart) + 1
  const nextRelease = changelog.indexOf('\n## [', notesStart)
  return changelog.slice(notesStart, nextRelease === -1 ? undefined : nextRelease).trim()
}

function main() {
  // GITHUB_REF_NAME is the tag that triggered the run; `git tag --points-at
  // HEAD` returns every tag on the commit, newline separated
  const tag = process.env.GITHUB_REF_NAME
  if (!tag) {
    throw new Error('GITHUB_REF_NAME is not set')
  }
  const version = tag.replace(/^v/, '')
  const changelog = fs.readFileSync('CHANGELOG.md', 'utf8')
  const notes = extractReleaseNotes(changelog, version)

  fs.writeFileSync('notes.md', notes)

  // any remaining arguments are attached to the release as assets
  const assets = process.argv.slice(2)

  execFileSync('gh', [
    'release', 'create', tag,
    '-F', 'notes.md',
    '--title', tag,
    '--discussion-category', 'Releases',
    ...assets,
  ], { stdio: 'inherit' })
}

module.exports = { extractReleaseNotes }

if (require.main === module) {
  main()
}
