let read = () => undefined;

export function get(ctx) {
  return read(ctx);
}

export function setReader(reader) {
  read = reader;
}

export default get;
