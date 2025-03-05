import { createHash } from "crypto";
import { BN } from "bn.js";
import elliptic from "elliptic";
import { AffinePoint } from "./affine";
import { CURVES, type CurveParams } from "./curves";
import { generateNonce } from "./nonce";

// Domain separation tags
// export const ENCODE_TO_CURVE_DST_FRONT = 0x01;
// export const ENCODE_TO_CURVE_DST_BACK = 0x00;
// export const PROOF_TO_HASH_DST_FRONT = 0x03;
// export const PROOF_TO_HASH_DST_BACK = 0x00;

/**
 * Verifiable Random Function (VRF) implementation
 * Based on the ECVRF-SECP256K1-SHA256-TAI specification
 */
export class VRF {
	private ec: elliptic.ec;
	private suiteID: number;
	private cLen: number;
	private ptLen: number;
	private hashFn: (data: Buffer) => Buffer;

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
		this.hashFn = (data: Buffer) => {
			const hasher = createHash(params.hashAlgorithm);
			hasher.update(data);
			return hasher.digest();
		};
	}

	/**
	 * Generate a VRF proof for a message using a private key
	 * @param secret Private key as a Buffer
	 * @param message Message to prove as a Buffer
	 * @returns VRF proof as a Buffer
	 */
	public prove(secret: Buffer, message: Buffer): Buffer {
		console.log("secret", secret.toString("hex"));

		// Step 1: derive public key from secret key as `Y = x * B`
		const publicKeyPoint = this.scalarBasePointMult(secret);
		const publicKeyBytes = publicKeyPoint.toBytes();
		console.log("publicKeyBytes", publicKeyBytes.toString("hex"));

		// Step 2: Encode to curve (using TAI)
		const HPoint = this.encodeToCurveTAI(publicKeyBytes, message);
		const HBytes = HPoint.toBytes();
		console.log("HBytes", HBytes.toString("hex"));
		// here: 0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4
		// rfc:  0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4

		// Step 4: Gamma = x * H
		const gammaPoint = this.scalarAffinePointMult(HPoint, secret);
		const gammaBytes = gammaPoint.toBytes();
		// console.log("gammaBytes", gammaBytes.toString('hex'));
		// here: 0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4
		// rfc:  0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4

		// Step 5: nonce (k generation)
		const kScalar = this.generateNonce(secret, HBytes);
		// console.log("kScalar", kScalar.toString('hex'));
		// here: 0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77
		// rfc:  0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77

		// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
		// U = k*B
		const uPoint = this.scalarBasePointMult(kScalar);
		const uBytes = uPoint.toBytes();
		// console.log("uBytes", uBytes.toString('hex'));
		// here: 02bb6a034f67643c6183c10f8b41dc4babf88bff154b674e377d90bde009c21672
		// rfc:  02bb6a034f67643c6183c10f8b41dc4babf88bff154b674e377d90bde009c21672

		// V = k*H
		const vPoint = this.scalarAffinePointMult(HPoint, kScalar);
		const vBytes = vPoint.toBytes();
		// console.log("vBytes", vBytes.toString('hex'));
		// here: 024651ef8b4a85a34cc696d5f1d56232a25bc95886cd9bf2b3502965ff90cd616e
		// rfc:  02893ebee7af9a0faa6da810da8a91f9d50e1dc071240c9706726820ff919e8394

		// Challenge generation
		const inputs = Buffer.concat([publicKeyBytes, HBytes, gammaBytes, uBytes, vBytes]);

		const cScalar = this.challengeGeneration(inputs, this.cLen);

		// Step 7: s = (k + c*x) mod q
		const mul = this.scalarMult(cScalar, secret);
		const sScalar = this.scalarAdd(mul, kScalar);

		// Step 8: encode (gamma, c, s)
		const result = Buffer.concat([gammaBytes, cScalar, sScalar]);

		// console.log("result (pi)", result.toString('hex'));
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
		if (y.isInfinity()) {
			return "INVALID";
		}

		// Step 4-6: Decode proof
		let decodedProof;
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

		const paddedCPrime = Buffer.alloc(32);
		c_prime.copy(paddedCPrime, 32 - c_prime.length); // Pad with zeros on the left

		return Buffer.compare(paddedCPrime, cScalar) === 0 ? this.gammaToHash(gammaPoint).toString("hex") : "INVALID";
	}

	// TODO: remove
	public decodePoint(point: Buffer): AffinePoint {
		return this.ec.curve.decodePoint(point);
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

	private decodeProof(pi: Buffer): {
		gamma: Buffer;
		cScalar: Buffer;
		sScalar: Buffer;
	} {
		const gammaOct = this.ptLen + 1;

		if (pi.length !== gammaOct + this.cLen * 3) {
			throw new Error("Invalid proof length");
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

	private challengeGeneration(points: Buffer, truncateLen: number): Buffer {
		// Step 1: challenge_generation_domain_separator_front = 0x02
		const challengeGenerationDomainSeparatorFront = 0x02;

		// Step 2: Initialize str = suiteString || challengeGenerationDomainSeparatorFront
		let pointBytes = Buffer.from([this.suiteID, challengeGenerationDomainSeparatorFront]);

		// Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || pointToString(PJ)
		pointBytes = Buffer.concat([pointBytes, points]);

		// Step 4-5: Add challenge_generation_domain_separator_back = 0x00
		pointBytes = Buffer.concat([pointBytes, Buffer.from([0x00])]);

		// Step 6: c_string = Hash(str)
		const cString = this.hashFn(pointBytes);

		// Step 7: truncated_c_string = c_string[0]...c_string[CLen-1]
		if (truncateLen > cString.length) {
			throw new Error("Truncate length exceeds hash length");
		}

		return cString.slice(0, truncateLen);
	}

	private encodeToCurveTAI(encodeToCurveSalt: Buffer, alpha: Buffer): AffinePoint {
		const encodeToCurveDSTFront = 0x01;
		const encodeToCurveDSTBack = 0x00;

		// Prepare the hash input
		const hashInput = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([encodeToCurveDSTFront]),
			encodeToCurveSalt,
			alpha,
			Buffer.from([0x00]), // Initial CTR=0
			Buffer.from([encodeToCurveDSTBack]),
		]);

		const ctrPosition = hashInput.length - 2;

		for (let i = 0; i <= 255; i++) {
			hashInput[ctrPosition] = i;
			const hashString = this.hashFn(hashInput);

			try {
				const point = this.tryHashToPoint(hashString);
				if (point) {
					return point;
				}
			} catch (err) {
				continue;
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
		// Convert AffinePoint to elliptic.js point format
		const ecPoint = this.ec.curve.point(point.x, point.y);

		// Perform multiplication
		const result = ecPoint.mul(k);

		// Convert back to AffinePoint
		return new AffinePoint(result.getX(), result.getY(), this.ec);
	}

	private scalarMult(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.mul(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", 32);
	}

	private scalarAdd(a: Buffer, b: Buffer): Buffer {
		const aBN = new BN(a);
		const bBN = new BN(b);
		const result = aBN.add(bBN).umod(this.ec.curve.n);
		return result.toArrayLike(Buffer, "be", 32);
	}

	private tryHashToPoint(data: Buffer): AffinePoint {
		const concatenatedData = Buffer.concat([Buffer.from([0x02]), data]);
		try {
			return AffinePoint.fromBytes(concatenatedData, this.ec);
		} catch (err) {
			throw new Error("Invalid point");
		}
	}

	private gammaToHash(point: any): Buffer {
		const proofToHashDSTFront = 0x03;
		const proofToHashDSTBack = 0x00;

		// Convert point to compressed format
		const pointBytes = Buffer.from(point.encode("array", true));

		const data = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([proofToHashDSTFront]),
			pointBytes,
			Buffer.from([proofToHashDSTBack]),
		]);

		return this.hashFn(data);
	}

	private generateNonce(secretKey: Buffer, data: Buffer): Buffer {
		return generateNonce(this.ec.curve.n, secretKey, this.hashFn(data));
	}
}

export { CURVES };
