import { createHash } from "node:crypto";
import BN from "bn.js";
import elliptic from "elliptic";
import { AffinePoint } from "./affine";
import { CURVES, type CurveParams, SuiteID } from "./curves";
import { generateNonce } from "./nonce";

/**
 * Verifiable Random Function (VRF) implementation
 * Based on RFC 9381 (Verifiable Random Functions (VRFs))
 * https://datatracker.ietf.org/doc/rfc9381/
 */
export class VRF {
	private ec: elliptic.ec;
	private suiteID: number;
	private cLen: number;
	private ptLen: number;
	private hashAlgorithm: string;
	private cofactor: BN;
	private scalarSize: number;

	// Domain separator constants defined per RFC 9381 Section 5.4
	private readonly CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT = 0x02;
	private readonly CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK = 0x00;
	private readonly ENCODE_TO_CURVE_DST_FRONT = 0x01;
	private readonly ENCODE_TO_CURVE_DST_BACK = 0x00;
	private readonly PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT = 0x03;
	private readonly PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK = 0x00;
	private readonly COMPRESSED_POINT_EVEN_Y_PREFIX = 0x02;

	/**
	 * Create a new VRF instance
	 * @param curve Curve parameters or name of predefined curve
	 */
	constructor(curve: CurveParams | string) {
		const params = typeof curve === "string" ? CURVES[curve] : curve;

		this.ec = new elliptic.ec(params.name);
		this.suiteID = params.suiteID;

		// Validate suite ID against RFC-defined values
		const validSuites = [
			SuiteID.ECVRF_P256_SHA256_TAI,
			SuiteID.ECVRF_P256_SHA512_TAI,
			SuiteID.ECVRF_SECP256K1_SHA256_TAI, // Extension beyond RFC
		];

		if (!validSuites.includes(this.suiteID)) {
			console.warn(`Suite ID ${this.suiteID} is not implemented in this library`);
		}

		this.cLen = params.cLen;
		this.ptLen = params.ptLen;
		this.hashAlgorithm = params.hashAlgorithm;
		this.cofactor = new BN(params.cofactor);

		// Derive scalar size from curve order
		this.scalarSize = Math.ceil(this.ec.curve.n.bitLength() / 8);
	}

	/**
	 * Generate a VRF proof for a message using a private key
	 * Implements algorithm from RFC 9381 Section 5.1
	 * @param secret Private key as a Buffer
	 * @param message Message to prove as a Buffer
	 * @returns VRF proof as a Buffer
	 */
	public prove(secret: Buffer, message: Buffer): Buffer {
		// Check secret key length
		if (secret.length !== this.scalarSize) {
			throw new Error(`Invalid secret key length: expected ${this.scalarSize}, got ${secret.length}`);
		}

		// Step 1: derive public key from secret key as `Y = x * B` (Section 5.1)
		const publicKeyPoint = this.scalarBasePointMult(secret);
		const publicKeyBytes = publicKeyPoint.toBytes();

		// Step 2: Encode to curve (using TAI) (Section 5.4.1)
		const HPoint = this.encodeToCurveTAI(publicKeyBytes, message);
		const HBytes = HPoint.toBytes();

		// Step 4: Gamma = x * H (Section 5.1)
		const gammaPoint = this.scalarAffinePointMult(HPoint, secret);
		const gammaBytes = gammaPoint.toBytes();

		// Step 5: k = ECVRF_nonce_generation (SK, h_string) (Section 5.4.2.2)
		// Note: This implementation uses RFC 6979 for nonce generation, which is
		// cryptographically sound but differs from the exact method in RFC 9381
		const kScalar = this.generateNonce(secret, HBytes);

		// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V) (Section 5.4.3)
		// U = k*B
		const uPoint = this.scalarBasePointMult(kScalar);
		const uBytes = uPoint.toBytes();

		// V = k*H
		const vPoint = this.scalarAffinePointMult(HPoint, kScalar);
		const vBytes = vPoint.toBytes();

		// Challenge generation
		const inputs = Buffer.concat([publicKeyBytes, HBytes, gammaBytes, uBytes, vBytes]);
		const cScalar = this.challengeGeneration(inputs, this.cLen);

		// Step 7: s = (k + c*x) mod q (Section 5.1)
		const mul = this.scalarMult(cScalar, secret);
		const sScalar = this.scalarAdd(mul, kScalar);

		// Step 8: encode (gamma, c, s) (Section 5.5)
		const result = Buffer.concat([gammaBytes, cScalar, sScalar]);

		return result;
	}

	/**
	 * Verify a VRF proof and return the resulting hash if valid
	 * Implements algorithm from RFC 9381 Section 5.3
	 * @param publicKey Public key as a Buffer
	 * @param proof VRF proof as a Buffer
	 * @param message Original message as a Buffer
	 * @returns Hash as a hex string if valid, "INVALID" if invalid
	 */
	public verify(publicKey: Buffer, proof: Buffer, message: Buffer): string {
		// Step 1-2: Decode public key (Section 5.3)
		const y = this.ec.curve.decodePoint(publicKey, "hex");

		// Step 3: Validate public key point (Section 5.3)
		if (y.mul(this.cofactor).isInfinity()) {
			return "INVALID";
		}

		// Step 4-6: Decode proof (Section 5.3, 5.5)
		let decodedProof: { gamma: Buffer; cScalar: Buffer; sScalar: Buffer };
		try {
			decodedProof = this.decodeProof(proof);
		} catch {
			return "INVALID";
		}

		const { gamma, cScalar, sScalar } = decodedProof;

		// Step 7: Hash to curve (Section 5.4.1)
		const H = this.encodeToCurveTAI(publicKey, message);

		// Step 8-9: Compute U and V (Section 5.3)
		const U = this.ec.g.mul(sScalar).add(y.mul(cScalar).neg());
		const hPoint = this.ec.curve.decodePoint(H.toBytes());
		const gammaPoint = this.ec.curve.decodePoint(gamma);
		const V = hPoint.mul(sScalar).add(gammaPoint.mul(cScalar).neg());

		// Step 10: Compute c' (Section 5.3, 5.4.3)
		const c_prime = this.challengeGeneration(
			Buffer.concat([
				publicKey,
				H.toBytes(),
				gamma,
				Buffer.from(U.encode("hex", true), "hex"),
				Buffer.from(V.encode("hex", true), "hex"),
			]),
			this.cLen,
		);

		// Compare c' to c from the proof (Section 5.3)
		const paddedCPrime = Buffer.alloc(this.scalarSize);
		c_prime.copy(paddedCPrime, this.scalarSize - c_prime.length);

		return Buffer.compare(paddedCPrime, cScalar) === 0 ? this.gammaToHash(gammaPoint).toString("hex") : "INVALID";
	}

	/**
	 * Convert a VRF proof to its corresponding hash output
	 * Implements algorithm from RFC 9381 Section 5.2
	 * @param proof VRF proof as a Buffer
	 * @returns Hash as a hex string
	 */
	public proofToHash(proof: Buffer): string {
		const { gamma } = this.decodeProof(proof);
		const gammaPoint = this.ec.curve.decodePoint(gamma);
		return this.gammaToHash(gammaPoint).toString("hex");
	}

	/**
	 * Generate a key pair for use with VRF
	 * @param entropy Optional entropy for key generation
	 * @returns Object containing secret key and public key
	 */
	public keygen(entropy?: Buffer): { secretKey: string; publicKey: string } {
		const keypair = entropy ? this.ec.genKeyPair({ entropy }) : this.ec.genKeyPair();

		return {
			secretKey: keypair.getPrivate("hex"),
			publicKey: keypair.getPublic(true, "hex"),
		};
	}

	// Private methods below

	/**
	 * Hash function used throughout the VRF
	 * @param data Data to hash
	 * @returns Hash output as a Buffer
	 */
	private hashFn(data: Buffer): Buffer {
		const hasher = createHash(this.hashAlgorithm);
		hasher.update(data);
		return hasher.digest();
	}

	/**
	 * Decode a VRF proof into its components
	 * Implements format from RFC 9381 Section 5.5
	 * @param pi Proof to decode
	 * @returns Decoded gamma, c, and s components
	 */
	private decodeProof(pi: Buffer): {
		gamma: Buffer;
		cScalar: Buffer;
		sScalar: Buffer;
	} {
		// Total compressed point size: ptLen (x-coordinate) + 1 (prefix)
		const gammaOct = this.ptLen + 1;

		// Expected proof length = point + challenge + scalar
		if (pi.length !== gammaOct + this.cLen + this.scalarSize) {
			throw new Error(`Invalid proof length: expected ${gammaOct + this.cLen + this.scalarSize}, got ${pi.length}`);
		}

		// Gamma point (compressed format)
		const gamma = Buffer.alloc(gammaOct);
		pi.copy(gamma, 0, 0, gammaOct);

		// C scalar (needs to be padded with leading zeroes to match scalar size)
		const cScalarPadding = Buffer.alloc(this.scalarSize - this.cLen);
		const cScalarData = pi.slice(gammaOct, gammaOct + this.cLen);
		const cScalar = Buffer.concat([cScalarPadding, cScalarData]);

		// S scalar
		const sScalar = Buffer.alloc(this.scalarSize);
		pi.copy(sScalar, 0, gammaOct + this.cLen);

		return { gamma, cScalar, sScalar };
	}

	/**
	 * Challenge generation function
	 * Implements algorithm from RFC 9381 Section 5.4.3
	 * @param points Concatenated point data
	 * @param truncateLen Length to truncate the output hash to
	 * @returns Challenge value as a Buffer
	 */
	private challengeGeneration(points: Buffer, truncateLen: number): Buffer {
		// Format per RFC 9381 Section 5.4.3
		const pointBytes = Buffer.concat([
			// Step 1-2: Initialize with suite string and domain separator
			Buffer.from([this.suiteID, this.CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT]),
			// Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || pointToString(PJ)
			points,
			// Step 4-5: Append back domain separator
			Buffer.from([this.CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]),
		]);

		// Step 6: c_string = Hash(str)
		const cString = this.hashFn(pointBytes);

		// Step 7: truncated_c_string = c_string[0]...c_string[CLen-1]
		if (truncateLen > cString.length) {
			throw new Error("Truncate length exceeds hash length");
		}

		return cString.slice(0, truncateLen);
	}

	/**
	 * Encode a message to an elliptic curve point using try-and-increment method
	 * Implements algorithm from RFC 9381 Section 5.4.1
	 * @param encodeToCurveSalt Salt value (usually the public key)
	 * @param alpha Message to encode
	 * @returns Point on the curve
	 */
	private encodeToCurveTAI(encodeToCurveSalt: Buffer, alpha: Buffer): AffinePoint {
		// Format per RFC 9381 Section 5.4.1
		const hashInput = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([this.ENCODE_TO_CURVE_DST_FRONT]),
			encodeToCurveSalt,
			alpha,
			Buffer.from([0x00]), // Initial CTR=0
			Buffer.from([this.ENCODE_TO_CURVE_DST_BACK]),
		]);

		const ctrPosition = hashInput.length - 2;

		for (let i = 0; i <= 255; i++) {
			hashInput[ctrPosition] = i;
			const hashString = this.hashFn(hashInput);

			try {
				const point = this.tryHashToPoint(hashString);
				if (point) {
					// Apply cofactor multiplication per RFC 9381 Section 5.4.1
					return point.multiply(this.cofactor);
				}
			} catch (_err) {
				// continue to next attempt
			}
		}

		throw new Error("EncodeToCurveTai: no solution found after 256 attempts");
	}

	/**
	 * Multiply the base point by a scalar
	 * @param scalar Scalar value as a Buffer
	 * @returns Resulting point
	 */
	private scalarBasePointMult(scalar: Buffer): AffinePoint {
		const k = new BN(scalar);
		const result = this.ec.g.mul(k);
		return new AffinePoint(result.getX(), result.getY(), this.ec);
	}

	/**
	 * Multiply a point by a scalar
	 * @param point Point to multiply
	 * @param scalar Scalar value as a Buffer
	 * @returns Resulting point
	 */
	private scalarAffinePointMult(point: AffinePoint, scalar: Buffer): AffinePoint {
		const k = new BN(scalar);
		return point.multiply(k);
	}

	/**
	 * Multiply two scalars modulo the curve order
	 * @param a First scalar
	 * @param b Second scalar
	 * @returns Product as a Buffer
	 */
	private scalarMult(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.mul(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", this.scalarSize);
	}

	/**
	 * Add two scalars modulo the curve order
	 * @param a First scalar
	 * @param b Second scalar
	 * @returns Sum as a Buffer
	 */
	private scalarAdd(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.add(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", this.scalarSize);
	}

	/**
	 * Try to convert a hash to a point on the curve
	 * @param data Hash data
	 * @returns Point on the curve if successful
	 */
	private tryHashToPoint(data: Buffer): AffinePoint {
		const concatenatedData = Buffer.concat([Buffer.from([this.COMPRESSED_POINT_EVEN_Y_PREFIX]), data]);
		try {
			return AffinePoint.fromBytes(concatenatedData, this.ec);
		} catch (err) {
			const errorMessage = err instanceof Error ? err.message : String(err);
			throw new Error(`Failed to hash to point: ${errorMessage}`);
		}
	}

	/**
	 * Convert a gamma point to its corresponding hash output
	 * Implements algorithm from RFC 9381 Section 5.2
	 * @param gamma Gamma point
	 * @returns Hash output as a Buffer
	 */
	private gammaToHash(gamma: elliptic.curve.base.BasePoint): Buffer {
		// Apply cofactor multiplication to ensure point is in the correct subgroup
		// This should be unnecessary if properly implemented elsewhere but included for safety
		const cofactorGamma = gamma.mul(this.cofactor);

		// Convert point to compressed format
		const pointBytes = Buffer.from(cofactorGamma.encode("array", true));

		// Format per RFC 9381 Section 5.2
		const data = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT]),
			pointBytes,
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK]),
		]);

		return this.hashFn(data);
	}

	/**
	 * Generate a deterministic nonce for ECDSA signatures
	 * Note: This uses RFC 6979 which differs from RFC 9381 Section 5.4.2.2
	 * Both methods are cryptographically sound for generating deterministic nonces
	 * @param secretKey Secret key
	 * @param data Input data
	 * @returns Nonce as a Buffer
	 */
	private generateNonce(secretKey: Buffer, data: Buffer): Buffer {
		return generateNonce(this.ec.curve.n, secretKey, this.hashFn(data), this.hashAlgorithm);
	}
}

export { CURVES, SuiteID };
