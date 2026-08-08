import { Readable } from 'node:stream';

import { expect } from 'chai';
import raw from 'raw-body';

/*
 * lib/shared/selective_body.js used raw-body to read request bodies with a
 * 56kb cap. raw-body is kept as a devDependency so the replacement can be held
 * to it: for every scenario below both must agree on the decoded body, or both
 * must fail.
 *
 * selective_body.js re-throws every failure as InvalidRequest, so what has to
 * match is success/failure and the decoded value - not raw-body's status codes.
 *
 * This drives both implementations with synthetic streams rather than over a
 * socket, the way raw-body's own tests do: the interesting cases (declared
 * length longer than the body, mid-stream abort) cannot be framed over real
 * HTTP without the request simply never completing.
 */

const LIMIT = 56 * 1024;

// kept in sync with lib/shared/selective_body.js
async function readBody(req, length, charset) {
  if (req.readableEncoding) throw new Error('stream encoding should not be set');
  if (length !== undefined && length > LIMIT) throw new Error('request entity too large');

  const chunks = [];
  let received = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    received += chunk.length;
    if (received > LIMIT) throw new Error('request entity too large');
    if (length !== undefined && received > length) throw new Error('request size did not match content length');
    chunks.push(chunk);
  }
  if (length !== undefined && received !== length) throw new Error('request size did not match content length');

  const body = Buffer.concat(chunks, received);
  return charset ? new TextDecoder(charset).decode(body) : body;
}

const stream = (chunks, { error } = {}) => new Readable({
  read() {
    for (const chunk of chunks) this.push(chunk);
    if (error) this.destroy(error);
    else this.push(null);
  },
});

const chunked = (buffer, size) => {
  const out = [];
  for (let i = 0; i < buffer.length; i += size) out.push(buffer.subarray(i, i + size));
  return out.length ? out : [Buffer.alloc(0)];
};

const CASES = [
  { name: 'utf-8 form body', chunks: [Buffer.from('grant_type=authorization_code&code=abc')], charset: 'utf-8' },
  { name: 'json body', chunks: [Buffer.from('{"a":1}')], charset: 'utf-8' },
  { name: 'no charset returns a buffer', chunks: [Buffer.from('grant_type=x')], charset: '' },
  { name: 'empty body', chunks: [Buffer.alloc(0)], charset: 'utf-8' },
  { name: 'utf-8 multibyte', chunks: [Buffer.from('a=ünïcödé✓😀')], charset: 'utf-8' },
  { name: 'utf-8 BOM', chunks: [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('a=b')])], charset: 'utf-8' },
  { name: 'multibyte split across chunks', chunks: chunked(Buffer.from('a=ünïcödé✓😀'), 1), charset: 'utf-8' },
  { name: 'iso-8859-2', chunks: [Buffer.from([0x61, 0x3d, 0xe1, 0xe9])], charset: 'iso-8859-2' },
  { name: 'windows-1252', chunks: [Buffer.from([0x61, 0x3d, 0x93, 0x94])], charset: 'windows-1252' },
  { name: 'shift_jis', chunks: [Buffer.from([0x61, 0x3d, 0x82, 0xa0])], charset: 'shift_jis' },
  { name: 'utf-16le', chunks: [Buffer.from('a=b', 'utf16le')], charset: 'utf-16le' },
  { name: 'invalid utf-8 bytes', chunks: [Buffer.from([0x61, 0x3d, 0xff, 0xfe])], charset: 'utf-8' },
  { name: 'unsupported charset', chunks: [Buffer.from('a=b')], charset: 'not-a-real-charset' },
  { name: 'exactly at the limit', chunks: [Buffer.alloc(LIMIT, 0x61)], charset: 'utf-8' },
  { name: 'one byte over the limit', chunks: [Buffer.alloc(LIMIT + 1, 0x61)], charset: 'utf-8' },
  { name: 'well over the limit', chunks: chunked(Buffer.alloc(LIMIT * 3, 0x61), 4096), charset: 'utf-8' },
  { name: 'limit crossed mid-stream', chunks: chunked(Buffer.alloc(LIMIT + 100, 0x61), 8192), charset: 'utf-8' },
  { name: 'declared length matches', chunks: [Buffer.from('aaa')], length: 3, charset: 'utf-8' },
  { name: 'declared length shorter than body', chunks: [Buffer.from('aaaaaaaaaa')], length: 3, charset: 'utf-8' },
  { name: 'declared length longer than body', chunks: [Buffer.from('aaa')], length: 10, charset: 'utf-8' },
  { name: 'declared length over the limit', chunks: [Buffer.from('aaa')], length: LIMIT + 1, charset: 'utf-8' },
  { name: 'declared length zero', chunks: [Buffer.alloc(0)], length: 0, charset: 'utf-8' },
  { name: 'stream errors mid-body', chunks: [Buffer.from('aa')], error: new Error('aborted'), charset: 'utf-8' },
];

const settle = async (promise) => {
  try {
    const value = await promise;
    return { ok: true, value: Buffer.isBuffer(value) ? `buffer:${value.toString('hex')}` : `string:${value}` };
  } catch {
    return { ok: false };
  }
};

describe('request body reading matches raw-body', () => {
  for (const testCase of CASES) {
    it(testCase.name, async () => {
      const { chunks, length, charset, error } = testCase;

      const theirs = await settle(raw(stream(chunks, { error }), {
        length, limit: '56kb', encoding: charset || undefined,
      }));
      const mine = await settle(readBody(stream(chunks, { error }), length, charset));

      expect(mine.ok, `raw-body ok=${theirs.ok}, replacement ok=${mine.ok}`).to.equal(theirs.ok);
      if (theirs.ok) expect(mine.value).to.equal(theirs.value);
    });
  }

  it('does not destroy the stream when it bails early', async () => {
    // a stream that never ends, so that being destroyed can only be the
    // iterator's doing and not autoDestroy firing on a natural end
    const source = new Readable({ read() { this.push(Buffer.alloc(8192, 0x61)); } });

    const result = await settle(readBody(source, undefined, 'utf-8'));

    expect(result.ok, 'should have bailed on the limit').to.equal(false);
    expect(source.destroyed, 'the error response still has to be written').to.equal(false);
    source.destroy();
  });

  it('rejects a stream that already has an encoding set', async () => {
    const source = stream([Buffer.from('a=b')]);
    source.setEncoding('utf8');
    expect((await settle(readBody(source, undefined, 'utf-8'))).ok).to.equal(false);
  });
});
