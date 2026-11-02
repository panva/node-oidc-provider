import { readFileSync } from 'node:fs';

import { parse } from '@babel/parser';

// node:test deliberately ignores .only without --test-only. CI must reject it.
export default function assertNoFocusedTests(files) {
  for (const file of files) {
    const tree = parse(readFileSync(file, 'utf8'), { sourceType: 'module' });
    const testFunctions = new Set(['describe', 'it', 'test', 'suite']);
    for (const node of tree.program.body) {
      if (node.type === 'ImportDeclaration' && node.source.value === 'node:test') {
        for (const specifier of node.specifiers) testFunctions.add(specifier.local.name);
      }
    }
    const property = (node) => node.computed ? node.property.value : node.property.name;
    const isTest = (node) => (
      (node.type === 'Identifier' && testFunctions.has(node.name))
      || (['MemberExpression', 'OptionalMemberExpression'].includes(node.type) && (
        isTest(node.object) || ['test', 'describe', 'it', 'suite'].includes(property(node))
      ))
    );
    function visit(node) {
      if (!node || typeof node !== 'object') return;
      if (
        ['MemberExpression', 'OptionalMemberExpression'].includes(node.type)
        && property(node) === 'only' && isTest(node.object)
      ) throw new Error(`focused test in ${file}:${node.loc.start.line}`);
      if (
        node.type === 'CallExpression'
        && ['MemberExpression', 'OptionalMemberExpression'].includes(node.callee.type)
        && property(node.callee) === 'runOnly'
        && !(node.arguments[0]?.type === 'BooleanLiteral' && node.arguments[0].value === false)
      ) throw new Error(`focused test in ${file}:${node.loc.start.line}`);
      if (node.type === 'CallExpression' && isTest(node.callee)) {
        const focusedCall = node.callee.type === 'MemberExpression' && property(node.callee) === 'only';
        const focusedOption = node.arguments.some((argument) => (
          argument.type === 'ObjectExpression' && argument.properties.some((entry) => (
            entry.type === 'ObjectProperty'
            && (entry.key.name === 'only' || entry.key.value === 'only')
            && !(entry.value.type === 'BooleanLiteral' && entry.value.value === false)
          ))
        ));
        if (focusedCall || focusedOption) throw new Error(`focused test in ${file}:${node.loc.start.line}`);
      }
      for (const value of Object.values(node)) {
        if (Array.isArray(value)) value.forEach(visit);
        else if (value && typeof value === 'object') visit(value);
      }
    }
    visit(tree);
  }
}
