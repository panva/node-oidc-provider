import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
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
    .map((node) => node.type === 'ExportNamedDeclaration' || node.type === 'ExportDefaultDeclaration' ? node.declaration : node)
    .find((node) => node?.type === type && node.id?.name === name);
}

function indexFixture() {
  return {
    fragments: {
      contracts: 'export interface Configuration {}',
      providerMembers: 'extension(): void;',
      relatedContracts: 'export interface Related {}',
      clientAuthMethods: 'export type ClientAuthMethod = "none";',
      oidcContext: 'export declare class OIDCContext {}',
    },
    template: `export interface JWK { pub?: string; }
// @generate contracts
export declare class Provider {
    // @generate providerMembers
}
// @generate relatedContracts
// @generate clientAuthMethods
// @generate oidcContext
`,
  };
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

const sourceAvailable = existsSync(generatorUrl) && existsSync(typeContractsUrl) && existsSync(eventSourceUrl);

describe('provider-owned type contracts', () => {
  let artifact;
  let index;
  let events;
  let renderEventsDocumentation;
  let renderIndexDeclaration;
  let readConfigurationContract;
  let validateEvents;

  before(async () => {
    if (!sourceAvailable) return;
    artifact = JSON.parse(generateTypes());
    index = parse(artifact.files['index.d.ts'], parserOptions);
    ({ default: events } = await import(eventSourceUrl.href));
    ({ readConfigurationContract, renderEventsDocumentation, renderIndexDeclaration, validateEvents } = await import(typeContractsUrl.href));
  }, { timeout: 3000 });

  it('emits a deterministic, versioned, hash-valid artifact without rewriting documentation', { timeout: 3000, skip: !sourceAvailable }, () => {
    const readme = readFileSync(readmeUrl);
    const eventDocumentation = readFileSync(eventsDocumentationUrl);
    const output = generateTypes();
    const repeated = generateTypes();

    assert.equal(output, repeated);
    assert.deepEqual(readFileSync(readmeUrl), readme);
    assert.deepEqual(readFileSync(eventsDocumentationUrl), eventDocumentation);

    const parsed = JSON.parse(output);
    assert.deepEqual(Object.keys(parsed), [
      'schemaVersion',
      'providerVersion',
      'hash',
      'files',
    ]);
    assert.equal(parsed.schemaVersion, 4);
    assert.equal(parsed.providerVersion, JSON.parse(readFileSync(packageUrl)).version);
    assert.match(parsed.hash, /^[a-f0-9]{64}$/);
    assert.deepEqual(Object.keys(parsed.files), [
      'index.d.ts',
      'lib/helpers/grants.d.ts',
      'oidc-provider-tests.ts',
    ]);

    for (const source of Object.values(parsed.files)) {
      assert.equal(typeof source, 'string');
      assert.notEqual(source.length, 0);
      parse(source, parserOptions);
    }

    const payload = { files: parsed.files };
    assert.equal(parsed.hash, createHash('sha256').update(JSON.stringify(payload)).digest('hex'));

    const contracts = parse(parsed.files['index.d.ts'], parserOptions);

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
      assert.equal(properties.length, 4);
      assert.equal(properties.every((property) => hasJSDocContaining(property, expected)), true);
    }

    const inactiveRar = declaration(
      contracts,
      'TSInterfaceDeclaration',
      'RichAuthorizationRequestsInactiveConfiguration',
    );
    const [inactiveTypes] = propertySignatures(inactiveRar, 'types');
    assert.notEqual(inactiveTypes, undefined);
    assert.equal(hasJSDocContaining(inactiveTypes, 'authorization details type identifiers'), true);
    assert.doesNotMatch(parsed.files['index.d.ts'], /@configuration-(?:path|docs|dynamic)|@generate\b|(?:BEGIN|END) GENERATED OIDC-PROVIDER/);
  });

  it('copies the grant-helper declaration byte-for-byte', { timeout: 3000, skip: !sourceAvailable }, () => {
    assert.equal(artifact.files['lib/helpers/grants.d.ts'], readFileSync(grantsSourceUrl, 'utf8').replaceAll('\r\n', '\n'));
  });

  it('carries the client authentication and context declarations required by the release', { timeout: 3000, skip: !sourceAvailable }, () => {
    const clientAuth = declaration(
      index,
      'TSTypeAliasDeclaration',
      'ClientAuthMethod',
    );
    assert.ok(clientAuth.typeAnnotation.types.map((type) => type.literal.value).includes('attest_jwt_client_auth_dpop'));

    const context = declaration(
      index,
      'ClassDeclaration',
      'OIDCContext',
    );
    const attestation = context.body.body.find((member) => member.key?.name === 'clientAttestation');
    ((actual) => { assert.ok("optional" in Object(actual)); assert.equal(actual.optional, true); assert.ok("readonly" in Object(actual)); assert.equal(actual.readonly, true); })(attestation);
    assert.ok(artifact.files['index.d.ts'].slice(context.start, context.end).includes('"dpop_combined"'));
  });

  it('owns JWK, JWKS, and client metadata declarations in the complete index', { timeout: 3000, skip: !sourceAvailable }, () => {
    const jwk = declaration(index, 'TSInterfaceDeclaration', 'JWK');
    for (const name of ['alg', 'kty', 'pub', 'priv', 'x', 'd']) {
      const [property] = propertySignatures(jwk, name);
      assert.equal(property.optional, true);
      assert.deepEqual(property.typeAnnotation.typeAnnotation.types.map(({ type }) => type), ['TSStringKeyword', 'TSUndefinedKeyword']);
    }
    const jwks = declaration(index, 'TSInterfaceDeclaration', 'JWKS');
    const [keys] = propertySignatures(jwks, 'keys');
    const array = keys.typeAnnotation.typeAnnotation;
    assert.equal(array.typeName.name, 'ReadonlyArray');
    assert.deepEqual(array.typeArguments.params[0].types.map(({ typeName }) => typeName.name), ['JWK', 'ExternalSigningKey']);

    const metadata = declaration(index, 'TSInterfaceDeclaration', 'AllClientMetadata');
    for (const name of [
      'client_id',
      'jwks',
      'token_endpoint_auth_method',
      'id_token_encrypted_response_alg',
      'authorization_details_types',
      'token_endpoint_auth_methods_supported',
    ]) {
      assert.equal(propertySignatures(metadata, name)[0]?.optional, true, name);
    }
    const clientMetadata = declaration(index, 'TSInterfaceDeclaration', 'ClientMetadata');
    assert.equal(clientMetadata.extends[0].expression.name, 'AllClientMetadata');
    assert.notEqual(propertySignatures(clientMetadata, 'client_id')[0].optional, true);
  });

  it('owns model declarations and the Provider core alongside generated extensions', { timeout: 3000, skip: !sourceAvailable }, () => {
    const provider = declaration(index, 'ClassDeclaration', 'Provider');
    assert.equal(provider.superClass.name, 'Koa');
    const initializer = provider.body.body.find((member) => member.kind === 'constructor');
    assert.deepEqual(initializer.params.map(({ name }) => name), ['issuer', 'configuration']);
    const issuer = provider.body.body.find((member) => member.key?.name === 'issuer');
    assert.equal(issuer.readonly, true);
    assert.equal(issuer.typeAnnotation.typeAnnotation.type, 'TSStringKeyword');

    for (const name of [
      'AccessToken', 'AuthorizationCode', 'BackchannelAuthenticationRequest', 'BaseToken',
      'Claims', 'Client', 'ClientCredentials', 'DeviceCode', 'Grant', 'IdToken',
      'InitialAccessToken', 'Interaction', 'PreAuthorizedCode', 'PushedAuthorizationRequest',
      'RefreshToken', 'RegistrationAccessToken', 'ReplayDetection', 'Session',
    ]) {
      assert.ok(declaration(index, 'ClassDeclaration', name), name);
      const exposed = provider.body.body.find((member) => member.key?.name === name);
      assert.equal(exposed?.readonly, true, name);
      assert.equal(exposed.typeAnnotation.typeAnnotation.exprName.name, name);
    }
    for (const name of [...extensionMethods, ...listenerMethods]) {
      assert.ok(provider.body.body.some((member) => member.type === 'TSDeclareMethod' && member.key?.name === name), name);
    }
    assert.ok(index.program.body.some((node) => node.type === 'ExportDefaultDeclaration' && node.declaration === provider));
    assert.ok(index.program.body.some((node) => node.type === 'ExportNamedDeclaration'
      && node.specifiers.some((specifier) => specifier.exported?.name === 'Provider')));
  });

  it('owns the signing and encryption algorithm unions', { timeout: 3000, skip: !sourceAvailable }, () => {
    for (const [name, expected] of [
      ['AsymmetricSigningAlgorithm', ['RS256', 'Ed25519', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']],
      ['SymmetricSigningAlgorithm', ['HS256', 'HS384', 'HS512']],
      ['EncryptionAlgValues', ['ECDH-ES', 'ECDH-ES+A256KW', 'RSA-OAEP-256', 'dir']],
      ['EncryptionEncValues', ['A128CBC-HS256', 'A128GCM', 'A256GCM']],
    ]) {
      const alias = declaration(index, 'TSTypeAliasDeclaration', name);
      const values = alias.typeAnnotation.types.map(({ literal }) => literal.value);
      for (const value of expected) assert.ok(values.includes(value), `${name}: ${value}`);
    }
    const signing = declaration(index, 'TSTypeAliasDeclaration', 'SigningAlgorithm');
    assert.deepEqual(signing.typeAnnotation.types.map(({ typeName }) => typeName.name), ['AsymmetricSigningAlgorithm', 'SymmetricSigningAlgorithm']);
  });

  it('renders all index fragments while preserving declarations owned by the template', { timeout: 3000, skip: !sourceAvailable }, () => {
    const { fragments, template } = indexFixture();
    const rendered = renderIndexDeclaration(fragments, template);
    const ast = parse(rendered, parserOptions);
    assert.ok(declaration(ast, 'TSInterfaceDeclaration', 'JWK'));
    assert.ok(declaration(ast, 'TSInterfaceDeclaration', 'Configuration'));
    assert.ok(declaration(ast, 'TSInterfaceDeclaration', 'Related'));
    assert.ok(declaration(ast, 'TSTypeAliasDeclaration', 'ClientAuthMethod'));
    assert.ok(declaration(ast, 'ClassDeclaration', 'OIDCContext'));
    const provider = declaration(ast, 'ClassDeclaration', 'Provider');
    assert.equal(provider.body.body[0].key.name, 'extension');
    assert.doesNotMatch(rendered, /@generate\b/);
  });

  it('rejects missing, extra, duplicate, and malformed index generation directives', { timeout: 3000, skip: !sourceAvailable }, () => {
    const { fragments, template } = indexFixture();
    for (const name of Object.keys(fragments)) {
      assert.throws(() => renderIndexDeclaration(fragments, template.replace(`// @generate ${name}`, '')), /missing declaration directives:/);
      assert.throws(() => renderIndexDeclaration(fragments, `${template}// @generate ${name}\n`), /duplicate declaration directive/);
    }
    assert.throws(() => renderIndexDeclaration(fragments, `${template}// @generate unknown\n`), /unknown declaration directive unknown/);
    assert.throws(() => renderIndexDeclaration(fragments, `${template}// @generate contracts extra\n`), /invalid declaration directive/);
  });

  it('rejects missing fragments and invalid TypeScript in the complete declaration', { timeout: 3000, skip: !sourceAvailable }, () => {
    const { fragments, template } = indexFixture();
    for (const name of Object.keys(fragments)) {
      assert.throws(() => renderIndexDeclaration({ ...fragments, [name]: '' }, template), /missing declaration fragment/);
    }
    assert.throws(() => renderIndexDeclaration({ ...fragments, contracts: 'export interface Configuration {' }, template), SyntaxError);
  });

  it('copies the canonical DT tests byte-for-byte', { timeout: 3000, skip: !sourceAvailable }, () => {
    assert.equal(artifact.files['oidc-provider-tests.ts'], readFileSync(new URL('types/oidc-provider-tests.ts', root), 'utf8').replaceAll('\r\n', '\n'));
  });

  it('rejects repeated configuration paths on unrelated declarations', { timeout: 3000, skip: !sourceAvailable }, () => {
    const source = `${readFileSync(configurationSourceUrl, 'utf8')}
interface UnrelatedConfiguration {
  // @configuration-path clientBasedCORS
  clientBasedCORS?: ((ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean) | undefined;
}
`;

    assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('configuration path clientBasedCORS is repeated by unrelated declarations')); return true; });
  });

  it('keeps documentation-only repetitions out of the configuration contract', { timeout: 3000, skip: !sourceAvailable }, () => {
    const contract = readConfigurationContract();

    assert.equal(contract.paths.get('features.openid4vci').length, 1);
    assert.equal(contract.paths.get('features.introspection').length, 1);
    assert.equal(contract.paths.get('features.richAuthorizationRequests').length, 1);
    assert.equal(contract.paths.get('features.richAuthorizationRequests.types').length, 2);
  });

  it('rejects documentation-only repetitions without a declared configuration path', { timeout: 3000, skip: !sourceAvailable }, () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      '// @configuration-docs features.openid4vci',
      '// @configuration-docs features.unknown.openid4vci',
    );

    assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('configuration-docs marker for features.unknown.openid4vci has no declared configuration path')); return true; });
  });

  it('rejects multiple documentation-rendering markers on one property', { timeout: 3000, skip: !sourceAvailable }, () => {
    const marker = '// @configuration-docs features.openid4vci';
    const configuration = readFileSync(configurationSourceUrl, 'utf8');

    for (const repeated of [marker, '// @configuration-path features.openid4vci']) {
      const source = configuration.replace(marker, `${marker}\n        ${repeated}`);
      assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('property openid4vci has multiple configuration documentation markers')); return true; });
    }
  });

  it('rejects documentation-only repetitions on unrelated declarations', { timeout: 3000, skip: !sourceAvailable }, () => {
    const source = `${readFileSync(configurationSourceUrl, 'utf8')}
interface UnrelatedConfiguration {
  // @configuration-docs clientBasedCORS
  clientBasedCORS?: ((ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean) | undefined;
}
`;

    assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('configuration docs for clientBasedCORS are repeated by unrelated declarations Configuration and UnrelatedConfiguration')); return true; });
  });

  it('rejects repeated configuration paths that widen requiredness', { timeout: 3000, skip: !sourceAvailable }, () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      'certificateBoundAccessTokens?: boolean | undefined;',
      'certificateBoundAccessTokens: boolean;',
    );

    assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('configuration path features.mTLS.certificateBoundAccessTokens makes a required property optional')); return true; });
  });

  it('rejects repeated configuration paths that widen Boolean literals', { timeout: 3000, skip: !sourceAvailable }, () => {
    const source = readFileSync(configurationSourceUrl, 'utf8').replace(
      'certificateBoundAccessTokens?: boolean | undefined;',
      'certificateBoundAccessTokens?: true | undefined;',
    );

    assert.throws(() => readConfigurationContract(source), (error) => { assert.ok(error.message.includes('configuration path features.mTLS.certificateBoundAccessTokens widens or changes its type')); return true; });
  });

  it('keeps every declared Provider extension method backed by the runtime prototype', { timeout: 3000, skip: !sourceAvailable }, () => {
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

    assert.deepEqual(methods.filter((name) => !listenerMethods.includes(name)), extensionMethods);
    for (const name of extensionMethods) {
      assert.equal(typeof Object.getOwnPropertyDescriptor(Provider.prototype, name)?.value, 'function');
    }
    for (const name of listenerMethods) {
      assert.equal(typeof Provider.prototype[name], 'function');
    }
  });

  it('matches interaction policy, error, and grant-helper value exports to runtime exports', { timeout: 3000, skip: !sourceAvailable }, () => {
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

    assert.ok(Array.isArray(interactionDeclarations));
    assert.ok(Array.isArray(errorDeclarations));
    assert.deepEqual(declarationValueNames(interactionDeclarations), Object.keys(interactionPolicy).sort());
    assert.deepEqual(declarationValueNames(errorDeclarations), Object.keys(errors).sort());
    assert.deepEqual(grantDeclarations, Object.keys(grantHelpers).sort());
  });

  it('covers every documented event with a static emission or known model lifecycle family', { timeout: 3000, skip: !sourceAvailable }, () => {
    const names = validateEvents();
    ((actual) => { assert.ok(Array.isArray(actual)); assert.notEqual(actual.length, 0); })(events);
    assert.equal(names.size, events.length);

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

    assert.deepEqual([...covered].sort(), [...names].sort());
  });

  it('renders the checked-in event documentation deterministically', { timeout: 3000, skip: !sourceAvailable }, () => {
    const rendered = renderEventsDocumentation();

    assert.equal(rendered, renderEventsDocumentation());
    assert.equal(rendered, readFileSync(eventsDocumentationUrl, 'utf8'));
  });

  it('keeps declaration templates out of the published package allowlist', { timeout: 3000, skip: !sourceAvailable }, () => {
    const packageJson = JSON.parse(readFileSync(packageUrl));

    assert.ok(!('types' in Object(packageJson)));
    assert.ok(!('typings' in Object(packageJson)));
    ((actual) => { assert.ok(Array.isArray(actual)); assert.notEqual(actual.length, 0); })(packageJson.files);
    assert.equal(packageJson.files.some((entry) => entry === 'types' || entry.startsWith('types/')), false);
  });
});
