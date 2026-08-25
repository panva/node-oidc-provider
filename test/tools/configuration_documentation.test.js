import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect } from 'chai';

const generator = fileURLToPath(new URL('../../docs/update-configuration.js', import.meta.url));
const testDirectory = fileURLToPath(new URL('.', import.meta.url));

function generate() {
  return execFileSync(process.execPath, [generator, '--configuration-json'], {
    cwd: testDirectory,
    encoding: 'utf8',
  });
}

describe('configuration documentation metadata', () => {
  it('emits every block as deterministic JSON without rewriting documentation', function () {
    const readme = new URL('../../docs/README.md', import.meta.url);
    if (!existsSync(readme)) {
      // docs/ is intentionally absent when test-dist runs against the package artifact.
      this.skip();
    }
    const before = readFileSync(readme);
    const output = generate();
    const entries = JSON.parse(output);

    expect(output).to.equal(generate());
    expect(readFileSync(readme)).to.deep.equal(before);
    expect(entries).to.be.an('array').that.is.not.empty;
    expect(new Set(entries.map(({ path }) => path)).size).to.equal(entries.length);

    expect(entries[0]).to.include({
      path: 'adapter',
      title: 'Storage Adapter',
      important: true,
      nodefault: true,
    });
    expect(entries[0]).not.to.have.property('type');
    expect(entries[0].description).to.include('Production deployments MUST provide a custom adapter');
    expect(entries[0].see).to.include('[The expected interface](/example/my_adapter.js)');
    expect(entries.at(-1)).to.include({ path: 'subjectTypes' });

    expect(entries.find(({ path }) => path === 'clientBasedCORS')).to.include({
      type: '(ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean',
    });
    expect(entries.find(({ path }) => path === 'findAccount')).to.nested.include({
      'placeholders.mustConfigure[0]': 'findAccount',
    });
    expect(entries.find(({ path }) => path === 'features.webMessageResponseMode'))
      .to.include({ experimental: true });

    for (const entry of entries) {
      expect(entry.path).to.be.a('string').that.is.not.empty;
      if (entry.type) expect(entry.type).to.be.a('string').that.is.not.empty;
      if (entry.title) expect(entry.title).to.be.a('string').that.is.not.empty;
      if (entry.description) expect(entry.description).to.be.a('string').that.is.not.empty;
      if (entry.see) expect(entry.see).to.be.an('array').that.is.not.empty;
      if (entry.recommendations) {
        expect(entry.recommendations).to.be.an('array').that.is.not.empty;
      }
    }
  });
});
