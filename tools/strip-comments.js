import { parse } from '@babel/parser';

const LINE_TERMINATORS = /\r\n|[\n\r\u2028\u2029]/gu;

export function stripComments(source) {
  const { comments = [] } = parse(source, {
    allowReturnOutsideFunction: true,
    attachComment: false,
    sourceType: 'module',
  });

  let result = '';
  let offset = 0;

  for (const { type, start, end } of comments) {
    result += source.slice(offset, start);
    const comment = source.slice(start, end);
    result += type === 'CommentLine'
      ? ''
      : (comment.match(LINE_TERMINATORS)?.join('') ?? ' ');
    offset = end;
  }

  return result + source.slice(offset);
}
