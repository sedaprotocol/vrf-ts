import BN from 'bn.js';
import { ec as EC, utils } from 'elliptic';
import { createHash } from "node:crypto";
import { AffinePoint } from './types';
import { generateNonce } from './nonce';

const secp256k1 = new EC('secp256k1');
export class VRFUtils {
    private curve: typeof secp256k1;
    private suiteID: number;
    private ptLen: number;
    public cLen: number;
    public hash: (data: Buffer) => Buffer = (data: Buffer) => {
        const hasher = createHash('sha256');
        hasher.update(data);
        return hasher.digest();
    };

    constructor(
        suiteID: number,
        ptLen: number,
        cLen: number,
        hash: (data: Buffer) => Buffer
    ) {
        this.curve = secp256k1;
        this.suiteID = suiteID;
        this.ptLen = ptLen;
        this.cLen = cLen;
        this.hash = hash;
    }

    // Decodes a VRF proof by extracting the gamma EC point, and parameters `c` and `s` as bytes
    decodeProof(pi: Buffer): {
        gamma: Buffer,
        cScalar: Buffer,
        sScalar: Buffer
    } {
        const gammaOct = this.ptLen + 1;

        if (pi.length !== gammaOct + this.cLen * 3) {
            throw new Error('invalid pi length');
        }

        // Gamma point
        const gamma = Buffer.alloc(gammaOct);
        pi.copy(gamma, 0, 0, gammaOct);

        // C scalar (needs to be padded with leading zeroes)
        const cScalarPadding = Buffer.alloc(this.ptLen - this.cLen);
        const cScalarData = pi.slice(gammaOct, gammaOct + this.cLen);
        const cScalar = Buffer.concat([cScalarPadding, cScalarData]);

        // S scalar
        const sScalar = Buffer.alloc(pi.length - gammaOct - this.cLen);
        pi.copy(sScalar, 0, gammaOct + this.cLen);

        return { gamma, cScalar, sScalar };
    }

    challengeGeneration(points: Buffer, truncateLen: number): Buffer {
        // Step 1: challenge_generation_domain_separator_front = 0x02
        const challengeGenerationDomainSeparatorFront = 0x02;

        // Step 2: Initialize str = suiteString || challengeGenerationDomainSeparatorFront
        let pointBytes = Buffer.from([this.suiteID, challengeGenerationDomainSeparatorFront]);

        // Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || pointToString(PJ)
        pointBytes = Buffer.concat([pointBytes, points]);

        // Step 4-5: Add challenge_generation_domain_separator_back = 0x00
        pointBytes = Buffer.concat([pointBytes, Buffer.from([0x00])]);

        // Step 6: c_string = Hash(str)
        const cString = this.hash(pointBytes);

        // Step 7: truncated_c_string = c_string[0]...c_string[CLen-1]
        if (truncateLen > cString.length) {
            throw new Error('truncate length exceeds hash length');
        }

        return cString.slice(0, truncateLen);
    }

    encodeToCurveTAI(encodeToCurveSalt: Buffer, alpha: Buffer): AffinePoint {
        const encodeToCurveDSTFront = 0x01; // Define these constants based on your needs
        const encodeToCurveDSTBack = 0x00;

        // Prepare the hash input
        let hashInput = Buffer.concat([
            Buffer.from([this.suiteID]),
            Buffer.from([encodeToCurveDSTFront]),
            encodeToCurveSalt,
            alpha,
            Buffer.from([0x00]), // Initial CTR=0
            Buffer.from([encodeToCurveDSTBack])
        ]);

        const ctrPosition = hashInput.length - 2;

        for (let i = 0; i <= 255; i++) {
            hashInput[ctrPosition] = i;
            const hashString = this.hash(hashInput);

            try {
                const point = this.tryHashToPoint(hashString);
                if (point) {
                    return point;
                }
            } catch (err) {
                continue;
            }
        }

        throw new Error('EncodeToCurveTai: no solution found');
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
    // scalarAffinePointMult(point: AffinePoint, scalar: Buffer): AffinePoint {
    //     const result = noble.ProjectivePoint.fromAffine({ x: BigInt(point.x.toString()), y: BigInt(point.y.toString()) });
    //     const sc = BigInt(new BN(scalar).toString());
    //     result.multiply(sc);
    //     return new AffinePoint(new BN(result.x.toString()), new BN(result.y.toString()));
    // }

    scalarAffinePointMult(point: AffinePoint, scalar: Buffer): AffinePoint {
        const k = new BN(scalar);
        const p = secp256k1.keyFromPublic({ x: point.x.toString(16), y: point.y.toString(16) }, 'hex').getPublic();
        const result = p.mul(k);
        return new AffinePoint(result.getX(), result.getY());
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

    /**
 * Add two scalars modulo curve order
 */
    scalarAdd(a: Buffer, b: Buffer): Buffer {
        const aBN = new BN(a);
        const bBN = new BN(b);
        const result = aBN.add(bBN).umod(this.curve.curve.n);
        return result.toArrayLike(Buffer, 'be', 32);
    }

    tryHashToPoint(data: Buffer): AffinePoint {
        const concatenatedData = Buffer.concat([Buffer.from([0x02]), data]);
        try {
            const affinePoint = AffinePoint.fromBytes(concatenatedData)
            return affinePoint;
        } catch (err) {
            throw new Error('Invalid point');
        }
    }

    gammaToHash(point: EC.KeyPair): Buffer {
        const proofToHashDSTFront = 0x03; // Define these constants based on your needs
        const proofToHashDSTBack = 0x00;

        const data = Buffer.concat([
            Buffer.from([this.suiteID]),
            Buffer.from([proofToHashDSTFront]),
            Buffer.from(point.getPublic().encode('array', true)), // Compressed point format
            Buffer.from([proofToHashDSTBack])
        ]);

        return this.hash(data);
    }

    generateNonce(secretKey: Buffer, data: Buffer): Buffer {
        const n = this.curve.n;

        if (!n) throw new Error('n is not available');

        return generateNonce(n, secretKey, this.hash(data));
    }

}

export function newK256VRF(): VRFUtils {
    return new VRFUtils(0xFE, 32, 16, (buffer) => {
        const hasher = createHash('sha256');
        hasher.update(buffer);
        return hasher.digest();
    })
}