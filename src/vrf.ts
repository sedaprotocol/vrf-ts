import { createHash } from "node:crypto";
import BN from "bn.js";
import elliptic from "elliptic";
import { AffinePoint } from "./affine";
import { CURVES, type CurveParams } from "./curves";
import { generateNonce } from "./nonce";

/**
 * Verifiable Random Function (VRF) implementation
 * Based on the ECVRF-SECP256K1-SHA256-TAI specification
 */
export class VRF {
	private ec: elliptic.ec;
	private suiteID: number;
	private cLen: number;
	private ptLen: number;
	private hashAlgorithm: string;
	private cofactor: BN;
	private scalarSize: number;

	// Domain separator constants should be defined at the class level
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
		this.cLen = params.cLen;
		this.ptLen = params.ptLen;
		this.hashAlgorithm = params.hashAlgorithm;
		this.cofactor = new BN(this.ec.curve.n.shrn(this.ec.curve.n.bitLength() - 1));

		// Derive scalar size from curve order
		this.scalarSize = Math.ceil(this.ec.curve.n.bitLength() / 8);
	}

	/**
	 * Generate a VRF proof for a message using a private key
	 * @param secret Private key as a Buffer
	 * @param message Message to prove as a Buffer
	 * @returns VRF proof as a Buffer
	 */
	public prove(secret: Buffer, message: Buffer): Buffer {
		// Check secret key length
		if (secret.length !== this.scalarSize) {
			throw new Error(`Invalid secret key length: expected ${this.scalarSize}, got ${secret.length}`);
		}

		// Step 1: derive public key from secret key as `Y = x * B`
		const publicKeyPoint = this.scalarBasePointMult(secret);
		const publicKeyBytes = publicKeyPoint.toBytes();

		// Step 2: Encode to curve (using TAI)
		const HPoint = this.encodeToCurveTAI(publicKeyBytes, message);
		const HBytes = HPoint.toBytes();

		// Step 4: Gamma = x * H
		const gammaPoint = this.scalarAffinePointMult(HPoint, secret);
		const gammaBytes = gammaPoint.toBytes();

		// Step 5: k = ECVRF_nonce_generation (SK, h_string)
		const kScalar = this.generateNonce(secret, HBytes);

		// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
		// U = k*B
		const uPoint = this.scalarBasePointMult(kScalar);
		const uBytes = uPoint.toBytes();

		// V = k*H
		const vPoint = this.scalarAffinePointMult(HPoint, kScalar);
		const vBytes = vPoint.toBytes();

		// Challenge generation
		const inputs = Buffer.concat([publicKeyBytes, HBytes, gammaBytes, uBytes, vBytes]);

		const cScalar = this.challengeGeneration(inputs, this.cLen);

		// Step 7: s = (k + c*x) mod q
		const mul = this.scalarMult(cScalar, secret);
		const sScalar = this.scalarAdd(mul, kScalar);

		// Step 8: encode (gamma, c, s)
		const result = Buffer.concat([gammaBytes, cScalar, sScalar]);

		return result;
	}

	/**
	 * Verify a VRF proof and return the resulting hash if valid
	 * @param publicKey Public key as a Buffer
	 * @param proof VRF proof as a Buffer
	 * @param message Original message as a Buffer
	 * @returns Hash as a hex string if valid, "INVALID" if invalid
	 */
	public verify(publicKey: Buffer, proof: Buffer, message: Buffer): string {
		// Step 1-2: Decode public key
		const y = this.ec.curve.decodePoint(publicKey, "hex");

		// Step 3: Validate public key point
		if (y.mul(this.cofactor).isInfinity()) {
			return "INVALID";
		}

		// Step 4-6: Decode proof
		let decodedProof: { gamma: Buffer; cScalar: Buffer; sScalar: Buffer };
		try {
			decodedProof = this.decodeProof(proof);
		} catch {
			return "INVALID";
		}

		const { gamma, cScalar, sScalar } = decodedProof;

		// Step 7: Hash to curve
		const H = this.encodeToCurveTAI(publicKey, message);

		// Step 8-9: Compute U and V
		const U = this.ec.g.mul(sScalar).add(y.mul(cScalar).neg());
		const hPoint = this.ec.curve.decodePoint(H.toBytes());
		const gammaPoint = this.ec.curve.decodePoint(gamma);
		const V = hPoint.mul(sScalar).add(gammaPoint.mul(cScalar).neg());

		// Step 10: Compute c'
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

		// No need to pad c_prime separately - compare directly with cScalar
		const paddedCPrime = Buffer.alloc(this.scalarSize);
		c_prime.copy(paddedCPrime, this.scalarSize - c_prime.length);

		return Buffer.compare(paddedCPrime, cScalar) === 0 ? this.gammaToHash(gammaPoint).toString("hex") : "INVALID";
	}

	/**
	 * Convert a VRF proof to its corresponding hash output
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

	private hashFn(data: Buffer): Buffer {
		const hasher = createHash(this.hashAlgorithm);
		hasher.update(data);
		return hasher.digest();
	}

	private decodeProof(pi: Buffer): {
		gamma: Buffer;
		cScalar: Buffer;
		sScalar: Buffer;
	} {
		const gammaOct = this.ptLen + 1;

		if (pi.length !== gammaOct + this.cLen + this.scalarSize) {
			throw new Error(`Invalid proof length: expected ${gammaOct + this.cLen + this.scalarSize}, got ${pi.length}`);
		}

		// Gamma point
		const gamma = Buffer.alloc(gammaOct);
		pi.copy(gamma, 0, 0, gammaOct);

		// C scalar (needs to be padded with leading zeroes)
		const cScalarPadding = Buffer.alloc(this.scalarSize - this.cLen);
		const cScalarData = pi.slice(gammaOct, gammaOct + this.cLen);
		const cScalar = Buffer.concat([cScalarPadding, cScalarData]);

		// S scalar
		const sScalar = Buffer.alloc(this.scalarSize);
		pi.copy(sScalar, 0, gammaOct + this.cLen);

		return { gamma, cScalar, sScalar };
	}

	private challengeGeneration(points: Buffer, truncateLen: number): Buffer {
		const pointBytes = Buffer.concat([
			// Step 1-2: Initialize str = suiteString || challengeGenerationDomainSeparatorFront
			Buffer.from([this.suiteID, this.CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT]),
			// Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || pointToString(PJ)
			points,
			// Step 4-5: str = str || challenge_generation_domain_separator_back
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

	private encodeToCurveTAI(encodeToCurveSalt: Buffer, alpha: Buffer): AffinePoint {
		// Use constants instead of hardcoded values
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
					// Apply cofactor multiplication
					return point.multiply(this.cofactor);
				}
			} catch (_err) {
				// continue;
			}
		}

		throw new Error("EncodeToCurveTai: no solution found");
	}

	private scalarBasePointMult(scalar: Buffer): AffinePoint {
		const k = new BN(scalar);
		const result = this.ec.g.mul(k);
		return new AffinePoint(result.getX(), result.getY(), this.ec);
	}

	public scalarAffinePointMult(point: AffinePoint, scalar: Buffer): AffinePoint {
		const k = new BN(scalar);
		return point.multiply(k);
	}

	private scalarMult(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.mul(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", this.scalarSize);
	}

	private scalarAdd(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.add(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", this.scalarSize);
	}

	private tryHashToPoint(data: Buffer): AffinePoint {
		const concatenatedData = Buffer.concat([Buffer.from([this.COMPRESSED_POINT_EVEN_Y_PREFIX]), data]);
		try {
			return AffinePoint.fromBytes(concatenatedData, this.ec);
		} catch (err) {
			const errorMessage = err instanceof Error ? err.message : String(err);
			throw new Error(`Failed to hash to point: ${errorMessage}`);
		}
	}

	private gammaToHash(gamma: elliptic.curve.base.BasePoint): Buffer {
		// Apply cofactor multiplication to ensure point is in the correct subgroup
		const cofactorGamma = gamma.mul(this.cofactor);

		// Convert point to compressed format
		const pointBytes = Buffer.from(cofactorGamma.encode("array", true));

		const data = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT]),
			pointBytes,
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK]),
		]);

		return this.hashFn(data);
	}

	private generateNonce(secretKey: Buffer, data: Buffer): Buffer {
		return generateNonce(this.ec.curve.n, secretKey, this.hashFn(data), this.hashAlgorithm);
	}
}

export { CURVES };
