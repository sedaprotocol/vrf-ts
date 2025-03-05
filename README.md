# vrf-ts

A TypeScript implementation of Verifiable Random Functions (VRFs) based on [RFC 9381](https://datatracker.ietf.org/doc/rfc9381/). This library implements elliptic curve VRFs with support for P-256 and secp256k1 curves.

## Features

- Full implementation of RFC 9381 VRF specifications
- Support for multiple elliptic curves (P-256, secp256k1)
- Deterministic proof generation
- Proof verification
- Hash output conversion
- Secure nonce generation using RFC 6979

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
import { VRF } from 'vrf-ts';

// Create a VRF instance with a supported curve
const vrf = new VRF('p256'); // or 'secp256k1'

// Generate a key pair
const keyPair = vrf.keygen();
console.log('Secret Key:', keyPair.secretKey);
console.log('Public Key:', keyPair.publicKey);

// Prove a message
const message = Buffer.from('example message');
const privateKey = Buffer.from(keyPair.secretKey, 'hex');
const proof = vrf.prove(privateKey, message);
console.log('VRF Proof:', proof.toString('hex'));

// Verify a proof
const publicKey = Buffer.from(keyPair.publicKey, 'hex');
const hash = vrf.verify(publicKey, proof, message);
console.log('VRF Hash:', hash);

// Convert proof to hash directly
const hashFromProof = vrf.proofToHash(proof);
console.log('Hash from Proof:', hashFromProof);
```

### Using with Different Curves

```typescript
// Using P-256 (NIST curve)
const vrfP256 = new VRF('p256');

// Using secp256k1 (Bitcoin/Ethereum curve)
const vrfSecp256k1 = new VRF('secp256k1');
```

## API Reference

### VRF Class

#### Constructor

```typescript
new VRF(curve: CurveParams | string)
```

- `curve`: Either a string name of a predefined curve ('p256', 'secp256k1') or a `CurveParams` object

#### Methods

- `keygen(entropy?: Buffer)`: Generate a new key pair
- `prove(secret: Buffer, message: Buffer)`: Generate a VRF proof
- `verify(publicKey: Buffer, proof: Buffer, message: Buffer)`: Verify a VRF proof
- `proofToHash(proof: Buffer)`: Convert a proof to its output hash

## Supported Curves

The library implements the following curves:

- `p256-sha256-tai`: NIST P-256 curve with SHA-256 (ECVRF-P256-SHA256-TAI from RFC 9381)
- `secp256k1-sha256-tai`: secp256k1 curve with SHA-256 (extension beyond RFC 9381)

Aliases:
- `p256`: Alias for `p256-sha256-tai`
- `secp256k1`: Alias for `secp256k1-sha256-tai`


## Development

To install dependencies:

```bash
bun install
```

To run tests:

```bash
bun test
```
