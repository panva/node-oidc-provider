// These typings are not 100% complete.

declare module 'node-jose' {
  export const JWA: {
      digest(): any;
      derive(): any;
      sign(): any;
      verify(): any;
      encrypt(): any;
      decrypt(): any;
  }

  export interface IJWEEncryptor {
      update (input: any): this;
      final(): Promise<string>;
  }

  export interface IJWEDecryptor {
      decrypt(input: string): Promise<IJWEDecryptResult>;
  }

  export interface IBaseResult {
      /**
       * the combined 'protected' and 'unprotected' header members
       */
      header: any;
      /**
       * the signed content
       */
      payload: Buffer;
      /**
       * The key used to verify the signature
       */
      key: IJWKKey;
  }

  export interface IJWEDecryptResult {
      /**
       * an array of the member names from the "protected" member
       */
      protected: string[];
      /**
       * the decrypted content (alternate)
       */
      plaintext: Buffer;
  }

  export const JWE: {
      createEncrypt(key: IJWKKey): IJWEEncryptor;
      createEncrypt(keys: IJWKKey[]): IJWEEncryptor;
      createEncrypt(options: {
          format?: 'compact' | 'flattened';
          zip?: boolean;


      }, key: IJWKKey): IJWEEncryptor;
      createDecrypt(key: IJWKKey): IJWEDecryptor;
  }

  export type KeyUse = 'sig' | 'enc' | 'desc';

  export interface IRawKey {
      alg: string;
      kty: string;
      use: KeyUse;

      // e and n make up the public key
      e: string;
      n: string;
  }

  export interface IKeyStoreGetFilter {
      kty?: string;
      use?: KeyUse;
      alg: string;
  }

  export interface IKeyStoreGetOptions extends IKeyStoreGetFilter {
      kid: string;
  }

  export interface IKeyStore {
      toJSON(exportPrivateKeys?: boolean): object;
      get (kid: string, filter?: IKeyStoreGetFilter): IRawKey;
      get (options: IKeyStoreGetOptions): IRawKey;
      all (options: Partial<IKeyStoreGetOptions>): IRawKey[];
      add (key: IRawKey): Promise<IJWKKey>;
      /**
       * @param key
       *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
       *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
       * @param form
       * is either a:
       * - "json" for a JSON stringified JWK
       * - "private" for a DER encoded 'raw' private key
       * - "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
       * - "public" for a DER encoded SPKI public key (alternate to 'spki')
       * - "spki" for a DER encoded SPKI public key
       * - "pkix" for a DER encoded PKIX X.509 certificate
       * - "x509" for a DER encoded PKIX X.509 certificate
       * - "pem" for a PEM encoded of PKCS8 / SPKI / PKIX
       */
      add (key: string | Buffer, form: 'json' | 'private' | 'pkcs8' | 'public' | 'spki' | 'pkix' | 'x509' | 'pem'): Promise<IJWKKey>;
      remove(key: IJWKKey)
  }

  export interface IJWKKey {
      /**
       * Defaults to false
       */
      toPEM(isPrivate?: boolean)
      keystore: IKeyStore;
      length: number;
      kty: string;
      kid: string;
      use: KeyUse;
      alg: string;
  }

  export const JWK: {
      isKeyStore(input: any): input is IKeyStore;
      isKey(input: any): input is IJWKKey;
      createKeyStore(): IKeyStore;
      asKeyStore(input: any): Promise<IKeyStore>;
      asKey (rawKey: IRawKey): Promise<IJWKKey>;
      /**
       * @param key
       *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
       *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
       * @param form
       * is either a:
       * - "json" for a JSON stringified JWK
       * - "private" for a DER encoded 'raw' private key
       * - "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
       * - "public" for a DER encoded SPKI public key (alternate to 'spki')
       * - "spki" for a DER encoded SPKI public key
       * - "pkix" for a DER encoded PKIX X.509 certificate
       * - "x509" for a DER encoded PKIX X.509 certificate
       * - "pem" for a PEM encoded of PKCS8 / SPKI / PKIX
       */
      asKey (key: string | Buffer, form: 'json' | 'private' | 'pkcs8' | 'public' | 'spki' | 'pkix' | 'x509' | 'pem'): Promise<IJWKKey>;
      MODE_SIGN: 'sign';
      MODE_VERIFY: 'verify';
      MODE_ENCRYPT: 'encrypt';
      MODE_DECRYPT: 'decrypt';
      MODE_WRAP: 'wrap';
      MODE_UNWRAP: 'wrap';
  }

  export interface IVerificationResult extends IBaseResult {
      /**
       * the verified signature
       */
      signature: Buffer;
  }

  export interface IJWSVerifier {
      verify (input: string): Promise<IVerificationResult>;
  }

  export const JWS: {
      /**
       * Using a keystore.
       */
      createVerify(keyStore: IKeyStore): IJWSVerifier;
      /**
       * To verify using an implied Key
       */
      createVerify(keyStore: IJWKKey): IJWSVerifier;
      /**
       * To verify using a key embedded in the JWS
       */
      createVerify(): IJWSVerifier;
  }

  export type TypedArray =
      Int8Array |
      Uint8Array |
      Uint8ClampedArray |
      Int16Array |
      Uint16Array |
      Int32Array |
      Uint32Array |
      Float32Array |
      Float64Array;

  export const util: {
      asBuffer (arr: ArrayBuffer | ArrayLike<number> | TypedArray): Buffer;
      base64url: {
          encode(data: Buffer, encoding?: string): string;
          decode(str: string): Buffer;
      },
      utf8: {
          encode (str: string): string;
          decode (str: string): string;
      }
      randomBytes(size: number): Buffer;
  }

  export const parse: {
      (input: string | Buffer | object): object;
      compact (input: string): object;
      json (input: object): object;
  }
}
