import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse } from '@babel/parser';
import { expect } from 'chai';

import * as errors from '../../lib/helpers/errors.js';
import * as grantHelpers from '../../lib/helpers/grants.js';
import * as interactionPolicy from '../../lib/helpers/interaction_policy/index.js';
import { Provider } from '../../lib/provider.js';

const root = new URL('../../', import.meta.url);
const generatorUrl = new URL('docs/update-configuration.js', root);
const typeContractsUrl = new URL('docs/type-contracts.js', root);
const eventSourceUrl = new URL('types/events.js', root);
const configurationSourceUrl = new URL('types/configuration.d.ts', root);
const providerSourceUrl = new URL('types/provider.d.ts', root);
const relatedSourceUrl = new URL('types/related.d.ts', root);
const grantsSourceUrl = new URL('types/lib/helpers/grants.d.ts', root);
const eventsDocumentationUrl = new URL('docs/events.md', root);
const readmeUrl = new URL('docs/README.md', root);
const packageUrl = new URL('package.json', root);
const libDirectory = fileURLToPath(new URL('lib/', root));

const parserOptions = {
  plugins: ['typescript'],
  sourceType: 'module',
};
const listenerMethods = [
  'addListener',
  'on',
  'once',
  'prependListener',
  'prependOnceListener',
];
const extensionMethods = [
  'urlFor',
  'pathFor',
  'cookieName',
  'registerResponseMode',
  'backchannelResult',
  'interactionResult',
  'interactionFinished',
  'interactionDetails',
  'registerGrantType',
];

function generateTypes() {
  return execFileSync(process.execPath, [fileURLToPath(generatorUrl), '--types-json'], {
    cwd: fileURLToPath(root),
    encoding: 'utf8',
  });
}

function exportedNamespace(ast, name) {
  return ast.program.body
    .find((node) => (
      node.type === 'ExportNamedDeclaration'
      && node.declaration?.type === 'TSModuleDeclaration'
      && node.declaration.id.type === 'Identifier'
      && node.declaration.id.name === name
    ))
    ?.declaration.body.body;
}

function declarationValueNames(members) {
  return members
    .filter((node) => node.type === 'ClassDeclaration' || node.type === 'TSDeclareFunction')
    .map((node) => node.id.name)
    .sort();
}

function declaration(ast, type, name) {
  return ast.program.body
    .map((node) => node.type === 'ExportNamedDeclaration' ? node.declaration : node)
    .find((node) => node?.type === type && node.id?.name === name);
}

function propertySignatures(node, name) {
  const result = [];

  function visit(value) {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== 'object') return;

    if (
      value.type === 'TSPropertySignature'
      && value.key.type === 'Identifier'
      && value.key.name === name
    ) {
      result.push(value);
    }

    for (const [key, child] of Object.entries(value)) {
      if (key !== 'loc' && !key.endsWith('Comments')) visit(child);
    }
  }

  visit(node);
  return result;
}

function hasJSDocContaining(node, expected) {
  return node.leadingComments?.some((comment) => (
    comment.type === 'CommentBlock'
    && comment.value.startsWith('*')
    && comment.value.includes(expected)
  ));
}

function javascriptFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return javascriptFiles(path);
    return path.endsWith('.js') ? [path] : [];
  });
}

describe('provider-owned type contracts', () => {
  let artifact;
  let events;
  let renderEventsDocumentation;
  let readConfigurationContract;
  let validateEvents;

  before(async function () {
    if (
      !existsSync(generatorUrl)
      || !existsSync(typeContractsUrl)
      || !existsSync(eventSourceUrl)
    ) {
      // docs/ and source-only types/ are intentionally absent from the package artifact.
      this.skip();
    }

    artifact = JSON.parse(generateTypes());
    ({ default: events } = await import(eventSourceUrl.href));
    ({ readConfigurationContract, renderEventsDocumentation, validateEvents } = await import(typeContractsUrl.href));
  });

  it('emits a deterministic, versioned, hash-valid artifact without rewriting documentation', () => {
    const readme = readFileSync(readmeUrl);
    const eventDocumentation = readFileSync(eventsDocumentationUrl);
    const output = generateTypes();
    const repeated = generateTypes();

    expect(output).to.equal(repeated);
    expect(readFileSync(readmeUrl)).to.deep.equal(readme);
    expect(readFileSync(eventsDocumentationUrl)).to.deep.equal(eventDocumentation);

    const parsed = JSON.parse(output);
    expect(Object.keys(parsed)).to.deep.equal([
      'schemaVersion',
      'providerVersion',
      'hash',
      'indexFragments',
      'files',
    ]);
    expect(parsed.schemaVersion).to.equal(1);
    expect(parsed.providerVersion).to.equal(JSON.parse(readFileSync(packageUrl)).version);
    expect(parsed.hash).to.match(/^[a-f0-9]{64}$/);
    expect(Object.keys(parsed.indexFragments)).to.deep.equal([
      'contracts',
      'providerMembers',
      'relatedContracts',
    ]);
    expect(Object.keys(parsed.files)).to.deep.equal(['lib/helpers/grants.d.ts']);

    for (const fragment of Object.values(parsed.indexFragments)) {
      expect(fragment).to.be.a('string').that.is.not.empty;
    }
    expect(parsed.files['lib/helpers/grants.d.ts']).to.be.a('string').that.is.not.empty;

    const payload = {
      indexFragments: parsed.indexFragments,
      files: parsed.files,
    };
    expect(parsed.hash).to.equal(
      createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
    );

    const contracts = parse(parsed.indexFragments.contracts, parserOptions);
    parse(`declare class Provider {\n${parsed.indexFragments.providerMembers}\n}`, parserOptions);
    parse(parsed.indexFragments.relatedContracts, parserOptions);
    parse(parsed.files['lib/helpers/grants.d.ts'], parserOptions);

    const conditionalFeatures = declaration(
      contracts,
      'TSTypeAliasDeclaration',
      'ConditionalRichAuthorizationRequestFeatures',
    );
    for (const [name, expected] of [
      ['openid4vci', 'OpenID for Verifiable Credential Issuance 1.0'],
      ['introspection', 'RFC7662'],
      ['richAuthorizationRequests', 'RFC9396'],
    ]) {
      const properties = propertySignatures(conditionalFeatures, name);
      expect(properties).to.have.length(4);
      expect(properties.every((property) => hasJSDocContaining(property, expected))).to.equal(true);
    }

    const inactiveRar = declaration(
      contracts,
      'TSInterfaceDeclaration',
      'RichAuthorizationRequestsInactiveConfiguration',
    );
    const [inactiveTypes] = propertySignatures(inactiveRar, 'types');
    expect(inactiveTypes).not.to.equal(undefined);
    expect(hasJSDocContaining(inactiveTypes, 'authorization details type identifiers')).to.equal(true);
    expect(parsed.indexFragments.contracts).not.to.include('@configuration-docs');
  });

  it('copies the grant-helper declaration byte-for-byte', () => {
    expect(artifact.files['lib/helpers/grants.d.ts']).to.equal(
      readFileSync(grantsSourceUrl, 'utf8').replaceAll('\r\n', '\n'),
    );
  });

  it('rejects repeated configuration paths on unrelated declarations', () => {
    const source = `${readFileSync(configurationSourceUrl, 'utf8')}
interface UnrelatedConfiguration {
  // @configuration-path clientBasedCORS
  clientBasedCORS?: ((ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean) | undefined;
}
`;

    expect(() => readConfigurationContract(source)).to.throw(
      'configuration path clientBasedCORS is repeated by unrelated declarations',
    );
  });

  it('keeps documentation-only repetitions out of the configuration contract', () => {
    const contract = readConfigurationContract();

    expect(contract.paths.get('features.openid4vci')).to.have.length(1);
    expect(contract.paths.get('features.introspection')).to.have.length(1);
    expect(contract.paths.get('features.richAuthorizationRequests')).to.have.length(1);
    expect(contract.paths.get('features.richAuthorizationRequests.types')).to.have.length(2);
  });

  it('rejects documentation-only repetitions without a declared configuration path', () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      '// @configuration-docs features.openid4vci',
      '// @configuration-docs features.unknown.openid4vci',
    );

    expect(() => readConfigurationContract(source)).to.throw(
      'configuration-docs marker for features.unknown.openid4vci has no declared configuration path',
    );
  });

  it('rejects multiple documentation-rendering markers on one property', () => {
    const marker = '// @configuration-docs features.openid4vci';
    const configuration = readFileSync(configurationSourceUrl, 'utf8');

    for (const repeated of [marker, '// @configuration-path features.openid4vci']) {
      const source = configuration.replace(marker, `${marker}\n        ${repeated}`);
      expect(() => readConfigurationContract(source)).to.throw(
        'property openid4vci has multiple configuration documentation markers',
      );
    }
  });

  it('rejects documentation-only repetitions on unrelated declarations', () => {
    const source = `${readFileSync(configurationSourceUrl, 'utf8')}
interface UnrelatedConfiguration {
  // @configuration-docs clientBasedCORS
  clientBasedCORS?: ((ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean) | undefined;
}
`;

    expect(() => readConfigurationContract(source)).to.throw(
      'configuration docs for clientBasedCORS are repeated by unrelated declarations Configuration and UnrelatedConfiguration',
    );
  });

  it('rejects repeated configuration paths that widen requiredness', () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      'certificateBoundAccessTokens?: boolean | undefined;',
      'certificateBoundAccessTokens: boolean;',
    );

    expect(() => readConfigurationContract(source)).to.throw(
      'configuration path features.mTLS.certificateBoundAccessTokens makes a required property optional',
    );
  });

  it('rejects repeated configuration paths that widen Boolean literals', () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      'certificateBoundAccessTokens?: boolean | undefined;',
      'certificateBoundAccessTokens?: true | undefined;',
    );

    expect(() => readConfigurationContract(source)).to.throw(
      'configuration path features.mTLS.certificateBoundAccessTokens widens or changes its type',
    );
  });

  it('keeps every declared Provider extension method backed by the runtime prototype', () => {
    const source = readFileSync(providerSourceUrl, 'utf8');
    const ast = parse(source, parserOptions);
    const wrapper = ast.program.body
      .find((node) => (
        node.type === 'ExportNamedDeclaration'
        && node.declaration?.type === 'ClassDeclaration'
        && node.declaration.id.name === 'ProviderExtensibilityContract'
      ))
      .declaration;
    const methods = wrapper.body.body
      .filter((node) => node.type === 'TSDeclareMethod')
      .map((node) => node.key.name);

    expect(methods.filter((name) => !listenerMethods.includes(name))).to.deep.equal(extensionMethods);
    for (const name of extensionMethods) {
      expect(Object.getOwnPropertyDescriptor(Provider.prototype, name)?.value).to.be.a('function');
    }
    for (const name of listenerMethods) {
      expect(Provider.prototype[name]).to.be.a('function');
    }
  });

  it('matches interaction policy, error, and grant-helper value exports to runtime exports', () => {
    const related = parse(readFileSync(relatedSourceUrl, 'utf8'), parserOptions);
    const interactionDeclarations = exportedNamespace(related, 'interactionPolicy');
    const errorDeclarations = exportedNamespace(related, 'errors');
    const grants = parse(readFileSync(grantsSourceUrl, 'utf8'), parserOptions);
    const grantDeclarations = grants.program.body
      .filter((node) => (
        node.type === 'ExportNamedDeclaration'
        && node.declaration?.type === 'TSDeclareFunction'
      ))
      .map((node) => node.declaration.id.name)
      .sort();

    expect(interactionDeclarations).to.be.an('array');
    expect(errorDeclarations).to.be.an('array');
    expect(declarationValueNames(interactionDeclarations)).to.deep.equal(
      Object.keys(interactionPolicy).sort(),
    );
    expect(declarationValueNames(errorDeclarations)).to.deep.equal(Object.keys(errors).sort());
    expect(grantDeclarations).to.deep.equal(Object.keys(grantHelpers).sort());
  });

  it('covers every documented event with a static emission or known model lifecycle family', () => {
    const names = validateEvents();
    expect(events).to.be.an('array').that.is.not.empty;
    expect(names.size).to.equal(events.length);

    const staticallyEmitted = new Set();
    const errorHandlerEvents = new Set();
    for (const file of javascriptFiles(libDirectory)) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(
        /(?:\bprovider|ctx\.oidc\.provider|oidc\.provider)\.emit\(\s*['"]([^'"]+)['"]/g,
      )) {
        staticallyEmitted.add(match[1]);
      }
      for (const match of source.matchAll(/\berror\(\s*['"]([^'"]+)['"]\)/g)) {
        errorHandlerEvents.add(match[1]);
      }
    }

    const modelLifecycleFamilies = {
      access_token: ['destroyed', 'saved', 'issued'],
      authorization_code: ['consumed', 'destroyed', 'saved'],
      backchannel_authentication_request: ['consumed', 'destroyed', 'saved'],
      client_credentials: ['destroyed', 'saved', 'issued'],
      device_code: ['consumed', 'destroyed', 'saved'],
      grant: ['destroyed', 'saved'],
      initial_access_token: ['destroyed', 'saved'],
      interaction: ['destroyed', 'saved'],
      pre_authorized_code: ['consumed', 'destroyed', 'saved'],
      pushed_authorization_request: ['destroyed', 'saved'],
      refresh_token: ['consumed', 'destroyed', 'saved'],
      registration_access_token: ['destroyed', 'saved'],
      replay_detection: ['destroyed', 'saved'],
      session: ['destroyed', 'saved'],
    };
    const modelLifecycleEvents = Object.entries(modelLifecycleFamilies)
      .flatMap(([model, lifecycle]) => lifecycle.map((event) => `${model}.${event}`));
    const covered = new Set([
      ...staticallyEmitted,
      ...errorHandlerEvents,
      ...modelLifecycleEvents,
    ]);

    expect([...covered].sort()).to.deep.equal([...names].sort());
  });

  it('renders the checked-in event documentation deterministically', () => {
    const rendered = renderEventsDocumentation();

    expect(rendered).to.equal(renderEventsDocumentation());
    expect(rendered).to.equal(readFileSync(eventsDocumentationUrl, 'utf8'));
  });

  it('keeps declaration templates out of the published package allowlist', () => {
    const packageJson = JSON.parse(readFileSync(packageUrl));

    expect(packageJson).not.to.have.property('types');
    expect(packageJson).not.to.have.property('typings');
    expect(packageJson.files).to.be.an('array').that.is.not.empty;
    expect(packageJson.files.some((entry) => entry === 'types' || entry.startsWith('types/')))
      .to.equal(false);
  });
});
