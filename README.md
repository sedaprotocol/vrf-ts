# vrf-ts

A TypeScript implementation of Verifiable Random Functions (VRFs) based on [RFC 9381](https://datatracker.ietf.org/doc/rfc9381/). This library implements an elliptic curve VRF using the secp256k1 curve.

## Features

- Implementation of RFC 9381 VRF specifications for secp256k1
- Deterministic proof generation using RFC 6979 for nonce generation
- Proof verification
- Hash output conversion
- Key pair generation

## Installation

```bash
npm install vrf-ts
# or
yarn add vrf-ts
# or
bun add vrf-ts
```

## Usage Examples

### Basic VRF Operations

```typescript
import { Secp256k1Vrf } from 'vrf-ts';

// Create a VRF instance
const vrf = new Secp256k1Vrf();

// Generate a key pair
const keyPair = vrf.keygen();
console.log('Secret Key:', keyPair.secretKey);
console.log('Public Key:', keyPair.publicKey);

// Prove a message
const message = Buffer.from('example message');
const privateKey = Buffer.from(keyPair.secretKey, 'hex');
const proof = vrf.prove(privateKey, message);
console.log('VRF Proof:', Buffer.from(proof).toString('hex'));

// Verify a proof
const publicKey = Buffer.from(keyPair.publicKey, 'hex');
const result = vrf.verify(publicKey, proof, message);
if (result.isValid) {
    console.log('VRF Hash:', result.hash);
} else {
    console.error('Verification failed:', result.reason);
}

// Convert proof to hash directly
const hashFromProof = vrf.proofToHash(proof);
console.log('Hash from Proof:', hashFromProof);
```

## API Reference

### Secp256k1Vrf Class

#### Constructor

```typescript
new Secp256k1Vrf()
```

#### Methods

- `keygen()`: Generate a new key pair
  - Returns: `{ secretKey: string, publicKey: string }` (hex encoded)
  
- `prove(secret: PrivKey, message: Bytes)`: Generate a VRF proof
  - Returns: `Bytes` (proof)
  
- `verify(publicKey: Hex, proof: Bytes, message: Bytes)`: Verify a VRF proof
  - Returns: `{ isValid: true, hash: string } | { isValid: false, reason: string }`
  
- `proofToHash(proof: Bytes)`: Convert a proof to its output hash
  - Returns: `string` (hex encoded hash)

## Implementation Details

This library implements the secp256k1 curve VRF with SHA-256 (extension beyond RFC 9381). It uses:

- [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) for elliptic curve operations
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) for cryptographic hashing
- RFC 6979 for deterministic nonce generation

## Development

To install dependencies:

```bash
bun install
```

To run tests:

```bash
bun test
```

## License

This project is open source and available under the [MIT License](LICENSE).
