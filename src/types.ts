import BN from 'bn.js';
import { createHash } from 'node:crypto';
import elliptic from 'elliptic';

// Domain separation tags
export const ENCODE_TO_CURVE_DST_FRONT = 0x01;
export const ENCODE_TO_CURVE_DST_BACK = 0x00;
export const PROOF_TO_HASH_DST_FRONT = 0x03;
export const PROOF_TO_HASH_DST_BACK = 0x00;

// Secp256k1 curve instance
export const secp256k1 = new elliptic.ec('secp256k1');

export class AffinePoint {
  constructor(public x: BN, public y: BN) {}

  toObject() {
    return {
        x: BigInt(this.x.toString()),
        y: BigInt(this.y.toString()),
    };
  }

  /**
   * Parse a compressed public key into an AffinePoint
   */
  static fromBytes(data: Buffer): AffinePoint {
    if (data.length !== 33) {
      throw new Error('Compressed point must be 33 bytes');
    }

    const point = secp256k1.keyFromPublic(data);
    if (!point) {
      throw new Error('Failed to unmarshal bytes to an elliptic curve point');
    }

    return new AffinePoint(point.getPublic().getX(), point.getPublic().getY());
  }

  /**
   * Convert the point to compressed SEC1 format
   */
  toBytes(): Buffer {
    // @ts-ignore
    const p = secp256k1.keyFromPublic({x: this.x.toBuffer(), y: this.y.toBuffer() });
    return Buffer.from(p.getPublic(true, 'hex'), 'hex');
  }
}

export class VRFStruct {
  private curve: typeof secp256k1;
  public readonly suiteID: number;
  public readonly cLen: number;
  public readonly ptLen: number;

  constructor() {
    this.curve = secp256k1;
    this.suiteID = 0xFE;
    this.cLen = 16;
    this.ptLen = 32;
  }

  /**
   * Get the order of the curve
   */
  N(): BN {
    return this.curve.curve.n;
  }

  /**
   * Hash the input using SHA256
   */
  hash(input: Buffer): Buffer {
    return createHash('sha256').update(input).digest();
  }

  /**
   * Convert a hash value to an integer modulo the curve order
   */
  hashToInt(hash: Buffer): BN {
    const orderBits = this.curve.curve.n.bitLength();
    const orderBytes = Math.ceil(orderBits / 8);
    
    let truncatedHash = hash;
    if (hash.length > orderBytes) {
      truncatedHash = hash.slice(0, orderBytes);
    }

    let num = new BN(truncatedHash);
    const excess = truncatedHash.length * 8 - orderBits;
    if (excess > 0) {
      num = num.shrn(excess);
    }

    return num;
  }

  /**
   * Add two affine points
   */
  affineAdd(a: AffinePoint, b: AffinePoint): AffinePoint {
    const p1 = secp256k1.keyFromPublic({x: a.x.toString(16), y: a.y.toString(16)}, 'hex').getPublic();
    const p2 = secp256k1.keyFromPublic({x: b.x.toString(16), y: b.y.toString(16)}, 'hex').getPublic();
    const result = p1.add(p2);
    return new AffinePoint(result.getX(), result.getY());
  }

  /**
   * Subtract two affine points
   */
  affineSub(a: AffinePoint, b: AffinePoint): AffinePoint {
    const p1 = secp256k1.keyFromPublic({x: a.x.toString(16), y: a.y.toString(16)}, 'hex').getPublic();
    const p2 = secp256k1.keyFromPublic({x: b.x.toString(16), y: b.y.toString(16)}, 'hex').getPublic();
    const result = p1.add(p2.neg());
    return new AffinePoint(result.getX(), result.getY());
  }

  /**
   * Multiply base point by scalar
   */
  scalarBasePointMult(scalar: Buffer): AffinePoint {
    const k = new BN(scalar);
    const result = this.curve.g.mul(k);
    return new AffinePoint(result.getX(), result.getY());
  }

  /**
   * Multiply point by scalar
   */
  scalarAffinePointMult(point: AffinePoint, scalar: Buffer): AffinePoint {
    const k = new BN(scalar);
    const p = secp256k1.keyFromPublic({x: point.x.toString(16), y: point.y.toString(16)}, 'hex').getPublic();
    const result = p.mul(k);
    return new AffinePoint(result.getX(), result.getY());
  }

  /**
   * Add two scalars modulo curve order
   */
  scalarAdd(a: Buffer, b: Buffer): Buffer {
    const aBN = new BN(a);
    const bBN = new BN(b);
    const result = aBN.add(bBN).umod(this.curve.curve.n);
    return result.toArrayLike(Buffer, 'be', 32);
  }

  /**
   * Multiply two scalars modulo curve order
   */
  scalarMult(a: Buffer, b: Buffer): Buffer {
    const aBN = new BN(a);
    const bBN = new BN(b);
    const result = aBN.mul(bBN).umod(this.curve.curve.n);
    return result.toArrayLike(Buffer, 'be', 32);
  }
}

/**
 * Create a new VRF struct with secp256k1 curve
 */
export function newK256VRF(): VRFStruct {
  return new VRFStruct();
}
