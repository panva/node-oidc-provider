# Security Policy

## Supported Versions

The following major versions are currently supported with security updates.

| Version                                                       | End-of-life |
| ------------------------------------------------------------- | ----------- |
| [v9.x](https://github.com/panva/node-oidc-provider/tree/v9.x) | TBD         |
| [v8.x](https://github.com/panva/node-oidc-provider/tree/v8.x) | 2026-04-30  |

End-of-life for the current release will be determined prior to the release of its successor.

## Reporting a Vulnerability

You should report vulnerabilities using the [Github UI](https://github.com/panva/node-oidc-provider/security/advisories/new) or via email panva.ip@gmail.com

## Threat Model

This section documents the threat model for `oidc-provider`, an OAuth 2.0 Authorization Server implementation for Node.js with OpenID Connect support.

### Purpose and Intended Users

This library is intended for developers building OAuth 2.0 Authorization Servers and OpenID Connect Providers. It provides a comprehensive, certified implementation that can be configured and extended to fit various use cases.

### Trust Assumptions

#### Underlying Cryptographic Primitives

This library trusts that the cryptographic implementations provided by the runtime and its dependencies are correct and secure. The library delegates cryptographic operations to these implementations and does not attempt to validate or verify their correctness.

#### Runtime Environment

The library assumes it is running in a trusted execution environment. The following are considered outside the scope of this library's threat model:

- **Prototype pollution attacks**: If an attacker can modify JavaScript prototypes, this is considered a vulnerability in the user's application code or the runtime environment, not in this library.
- **Debugger access**: If an attacker has debugger access to the running process, they can inspect memory, modify variables, and bypass security controls. This is a runtime-level compromise, not a library vulnerability.
- **Runtime compromise**: Attacks that compromise the JavaScript runtime itself (e.g., malicious runtime modifications, compromised Node.js binaries) are not considered attacks on this library.

#### Configuration and User Code

Configuration provided by users is considered trusted. This includes adapter implementations, client registrations, policies, and all other configuration options. The library does not validate that configuration choices are secure for the user's specific deployment context.

#### Storage Adapter

The storage adapter (for persisting tokens, sessions, grants, etc.) is user-provided code and is considered trusted. The security of stored data depends on the adapter implementation and the underlying storage system chosen by the user.

#### Side-Channel Attacks

This library delegates cryptographic operations to underlying libraries. Any resistance to side-channel attacks (timing attacks, cache attacks, etc.) is entirely dependent on the underlying cryptographic implementations and is outside the scope of this library.

### Security Guarantees

This library aims to provide the following security guarantees:

- **Specification compliance**: Correct implementation of OAuth 2.0, OpenID Connect, and related specifications (including FAPI 1.0/2.0, CIBA), validated through OpenID Foundation conformance testing.
- **Secure defaults**: The library ships with secure default settings that follow current best practices.
- **Protocol security mechanisms**: Correct implementation of security mechanisms including:
  - PKCE support and enforcement options
  - Secure token generation
  - Token binding (DPoP, mTLS)
  - Session management
  - Issuer identification
  - JWT validation
- **Input validation**: Validation of inputs from clients and end-users.

### Out of Scope

#### Key Management

This library does not handle key storage. Users are responsible for securely storing, managing, and rotating cryptographic keys.

#### Memory Clearing

This library does not guarantee that key material or other sensitive data is cleared from memory after use. Secure memory management is the responsibility of the user and the runtime environment.

### Threat Actors and Security Properties

This library aims to provide the security properties defined by the OAuth 2.0 and OpenID Connect specifications. For detailed security considerations, refer to [RFC 6819 (OAuth 2.0 Threat Model)](https://www.rfc-editor.org/rfc/rfc6819), [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html), and [OpenID Connect Core 1.0 Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html#Security).

### What is NOT Considered a Vulnerability

The following are explicitly **not** considered vulnerabilities in this library:

- **Prototype pollution** ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)): Attacks that exploit JavaScript prototype pollution are considered vulnerabilities in user application code or the runtime, not this library.
- **Object injection** ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)): Similar to prototype pollution, object injection attacks are outside the scope of this library.
- **Debugger/inspector access** ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)): If an attacker can attach a debugger to the process, they have already compromised the runtime environment.
- **Memory inspection**: Reading process memory, heap dumps, or core dumps to extract key material is a runtime-level attack.
- **Side-channel attacks** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)): Timing attacks, cache attacks, and other side-channel vulnerabilities in the underlying cryptographic implementations are not vulnerabilities in this library.
- **Compromised runtime environment**: Malicious or backdoored JavaScript runtimes, compromised system libraries, or tampered cryptographic implementations.
- **Supply chain attacks on the runtime** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): Compromised Node.js binaries or similar supply chain attacks on the execution environment.
- **Supply chain attacks on dependencies** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): This library has dependencies. Supply chain compromises of dependencies are not considered vulnerabilities in this library.
- **Denial of service via resource exhaustion** ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)): While the library validates inputs, it does not implement resource limits. Applications should implement their own rate limiting and resource management.
- **Misconfiguration**: Security issues arising from insecure configuration choices (e.g., weak policies, insecure client settings) are the user's responsibility.
- **Insecure adapter implementations**: Security issues in user-provided storage adapters are the user's responsibility.
