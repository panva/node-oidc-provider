import { customAlphabet, urlAlphabet } from 'nanoid';

const nanoid = customAlphabet(urlAlphabet, 43);

export default nanoid;
