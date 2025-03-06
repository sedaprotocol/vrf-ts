import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import { type Bytes, type Hex, type PrivKey, ProjectivePoint } from "@noble/secp256k1";
import {} from "@noble/secp256k1";
import { generateNonce } from "./nonce.js";

/**
 * Verifiable Random Function (VRF) implementation using @noble/secp256k1
 * Based on RFC 9381 (Verifiable Random Functions (VRFs))
 * https://datatracker.ietf.org/doc/rfc9381/
 *
 * This implementation focuses specifically on the secp256k1 curve.
 */
export class Secp256k1Vrf {
	/**
	 * Extension beyond RFC 9381 - secp256k1 with SHA-256 and TAI
	 * Note: This is not defined in RFC 9381 and is a custom extension
	 */
	private readonly suiteID = 0xfe;
	private readonly cLen = 16; // Challenge length
	private readonly scalarSize = 32; // 256 bits
	private readonly ptLen = 32; // Size of x-coordinate

	// Domain separator constants defined per RFC 9381 Section 5.4
	private readonly CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT = 0x02;
	private readonly CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK = 0x00;
	private readonly ENCODE_TO_CURVE_DST_FRONT = 0x01;
	private readonly ENCODE_TO_CURVE_DST_BACK = 0x00;
	private readonly PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT = 0x03;
	private readonly PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK = 0x00;
	private readonly COMPRESSED_POINT_EVEN_Y_PREFIX = 0x02;

	/**
	 * Generate a VRF proof for a message using a private key
	 * Implements algorithm from RFC 9381 Section 5.1
	 * @param secret Private key as bytes
	 * @param message Message to prove as bytes
	 * @returns VRF proof as bytes
	 */
	public prove(secret: PrivKey, message: Bytes): Bytes {
		// Validate the secret key
		let secretBigInt: bigint;
		try {
			secretBigInt = secp256k1.utils.normPrivateKeyToScalar(secret);
		} catch (error) {
			throw new Error(`Invalid secret key: ${error instanceof Error ? error.message : String(error)}`);
		}

		// Step 1: derive public key from secret key
		const publicKey = secp256k1.getPublicKey(secret);

		// Step 2: Encode to curve (using TAI)
		const hBytes = this.encodeToCurveTAI(publicKey, message);

		// Step 4: Gamma = x * H
		const hPoint = ProjectivePoint.fromHex(hBytes);
		const gammaPoint = hPoint.multiply(secretBigInt);

		// Step 5: Generate nonce (using RFC 6979)
		const kScalar = this.generateNonce(secretBigInt, hBytes);

		// Step 6: Challenge generation
		// U = k*B
		const kScalarBigInt = secp256k1.utils.normPrivateKeyToScalar(kScalar);
		const uPoint = ProjectivePoint.BASE.multiply(kScalarBigInt);

		// V = k*H
		const vPoint = hPoint.multiply(kScalarBigInt);

		// Convert points to compressed format
		const publicKeyBytes = publicKey;
		const hPointBytes = hBytes;
		const gammaPointBytes = gammaPoint.toRawBytes(true);
		const uPointBytes = uPoint.toRawBytes(true);
		const vPointBytes = vPoint.toRawBytes(true);

		// Challenge generation
		const inputs = Buffer.concat([publicKeyBytes, hPointBytes, gammaPointBytes, uPointBytes, vPointBytes]);
		const cScalar = this.challengeGeneration(inputs, this.cLen);
		const cBigInt = BigInt(`0x${Buffer.from(cScalar).toString("hex")}`);

		// Step 7: s = (k + c*x) mod q
		const kBigInt = secp256k1.utils.normPrivateKeyToScalar(kScalar);

		// Calculate s = (k + c*x) mod q
		const n = secp256k1.CURVE.n;
		const sBigInt = (kBigInt + ((cBigInt * secretBigInt) % n)) % n;
		const sHex = sBigInt.toString(16).padStart(this.scalarSize * 2, "0");
		const sScalar = Buffer.from(sHex, "hex");

		// Step 8: encode (gamma, c, s)
		return Buffer.concat([gammaPointBytes, cScalar, sScalar]);
	}

	/**
	 * Verify a VRF proof and return the resulting hash if valid
	 * Implements algorithm from RFC 9381 Section 5.3
	 * @param publicKey Public key as bytes
	 * @param proof VRF proof as bytes
	 * @param message Original message as bytes
	 * @returns Hash as a hex string if valid, "INVALID" if invalid
	 */
	public verify(publicKey: Hex, proof: Bytes, message: Bytes): string {
		try {
			// Step 1-2: Decode public key
			// Verify the public key is valid
			const publicKeyBytes = ProjectivePoint.fromHex(publicKey).toRawBytes(true);

			// Step 4-6: Decode proof
			const { gamma, cScalar, sScalar } = this.decodeProof(proof);

			// Step 7: Hash to curve
			const H = this.encodeToCurveTAI(publicKeyBytes, message);

			// Convert to noble/secp256k1 points
			const Y = ProjectivePoint.fromHex(publicKey);
			const Gamma = ProjectivePoint.fromHex(gamma);
			const HPoint = ProjectivePoint.fromHex(H);

			// Convert challenge and scalar to BigInt
			const cScalarBigInt = secp256k1.utils.normPrivateKeyToScalar(cScalar);
			const sScalarBigInt = secp256k1.utils.normPrivateKeyToScalar(sScalar);

			// Step 8-9: Compute U and V
			// U = sG - cY
			const sG = ProjectivePoint.BASE.multiply(sScalarBigInt);
			const cY = Y.multiply(cScalarBigInt);
			const U = sG.add(cY.negate());

			// V = sH - cGamma
			const sH = HPoint.multiply(sScalarBigInt);
			const cGamma = Gamma.multiply(cScalarBigInt);
			const V = sH.add(cGamma.negate());

			// Step 10: Compute c'
			const c_prime = this.challengeGeneration(
				Buffer.concat([publicKeyBytes, H, gamma, U.toRawBytes(true), V.toRawBytes(true)]),
				this.cLen,
			);

			// Compare c' to c from the proof
			const cPrimeBytes = Buffer.from(c_prime);
			const cScalarBytes = Buffer.from(cScalar).slice(this.scalarSize - this.cLen);

			return Buffer.compare(cPrimeBytes, cScalarBytes) === 0
				? Buffer.from(this.gammaToHash(gamma)).toString("hex")
				: "INVALID";
		} catch (error) {
			console.error(`VRF verification failed: ${error instanceof Error ? error.message : String(error)}`);
			console.debug("Verification details:", {
				publicKeyLength: publicKey.length,
				proofLength: proof.length,
				messageLength: message.length,
				error,
			});
			return "INVALID";
		}
	}

	/**
	 * Convert a VRF proof to its corresponding hash output
	 * Implements algorithm from RFC 9381 Section 5.2
	 * @param proof VRF proof as bytes
	 * @returns Hash output as a hex string
	 */
	public proofToHash(proof: Bytes): string {
		const { gamma } = this.decodeProof(proof);
		return Buffer.from(this.gammaToHash(gamma)).toString("hex");
	}

	/**
	 * Generate a key pair for use with VRF
	 * @returns Object containing secret key and public key as hex strings
	 */
	public keygen(): { secretKey: string; publicKey: string } {
		const privateKey = secp256k1.utils.randomPrivateKey();
		const publicKey = secp256k1.getPublicKey(privateKey, true); // Compressed format

		return {
			secretKey: Buffer.from(privateKey).toString("hex"),
			publicKey: Buffer.from(publicKey).toString("hex"),
		};
	}

	// Private helper methods

	/**
	 * Decode a VRF proof into its components
	 * @param pi Proof to decode as bytes
	 * @returns Decoded gamma, c, and s components as bytes
	 */
	private decodeProof(pi: Bytes): {
		gamma: Bytes;
		cScalar: Bytes;
		sScalar: Bytes;
	} {
		// Convert pi to Buffer if it's not already
		const piBuffer = Buffer.isBuffer(pi) ? pi : Buffer.from(pi);

		// Total compressed point size: ptLen (x-coordinate) + 1 (prefix)
		const gammaOct = this.ptLen + 1;

		// Expected proof length = point + challenge + scalar
		if (piBuffer.length !== gammaOct + this.cLen + this.scalarSize) {
			throw new Error(
				`Invalid proof length: expected ${gammaOct + this.cLen + this.scalarSize}, got ${piBuffer.length}`,
			);
		}

		// Gamma point (compressed format)
		const gamma = piBuffer.slice(0, gammaOct);

		// C scalar (needs to be padded with leading zeroes to match scalar size)
		const cScalar = Buffer.alloc(this.scalarSize);
		piBuffer.slice(gammaOct, gammaOct + this.cLen).copy(cScalar, this.scalarSize - this.cLen);

		// S scalar
		const sScalar = piBuffer.slice(gammaOct + this.cLen);

		return { gamma, cScalar, sScalar };
	}

	/**
	 * Challenge generation function
	 * @param points Concatenated point data as bytes
	 * @param truncateLen Length to truncate the output hash to
	 * @returns Challenge value as bytes
	 */
	private challengeGeneration(points: Bytes, truncateLen: number): Bytes {
		const pointBytes = Buffer.concat([
			Buffer.from([this.suiteID, this.CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT]),
			points,
			Buffer.from([this.CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]),
		]);

		const cString = sha256(pointBytes);

		if (truncateLen > cString.length) {
			throw new Error("Truncate length exceeds hash length");
		}

		return cString.slice(0, truncateLen);
	}

	/**
	 * Encode a message to an elliptic curve point using try-and-increment method
	 * @param encodeToCurveSalt Salt value (usually the public key) as bytes
	 * @param alpha Message to encode as bytes
	 * @returns Point on the curve as bytes
	 */
	private encodeToCurveTAI(encodeToCurveSalt: Bytes, alpha: Bytes): Bytes {
		// Prepare components for the hash input
		const prefix = Buffer.from([this.suiteID, this.ENCODE_TO_CURVE_DST_FRONT]);
		const suffix = Buffer.from([0x00, this.ENCODE_TO_CURVE_DST_BACK]); // Initial CTR=0

		// Concatenate all parts using Buffer.concat for better efficiency
		const hashInput = Buffer.concat([prefix, encodeToCurveSalt, alpha, suffix]);

		const ctrPosition = hashInput.length - 2;
		const candidatePoint = new Uint8Array(33);
		candidatePoint[0] = this.COMPRESSED_POINT_EVEN_Y_PREFIX;

		for (let i = 0; i <= 255; i++) {
			hashInput[ctrPosition] = i;
			const hashBytes = sha256(hashInput);

			try {
				// Copy hash bytes to candidatePoint
				candidatePoint.set(hashBytes.slice(0, 32), 1);

				// Try to create a valid point
				const point = ProjectivePoint.fromHex(candidatePoint);

				// No need to apply cofactor multiplication (Secp256k1 has cofactor 1)

				// Return point in compressed format
				return point.toRawBytes(true);
			} catch (_err) {
				// Continue to next attempt
			}
		}

		throw new Error("EncodeToCurveTai: no solution found after 256 attempts");
	}

	/**
	 * Generate a deterministic nonce for ECDSA signatures using RFC 6979
	 * @param secretKey Secret key
	 * @param data Input data
	 * @returns Nonce as bytes
	 */
	private generateNonce(secretKey: PrivKey, data: Bytes): Bytes {
		return generateNonce(secretKey, sha256(data));
	}

	/**
	 * Convert a gamma point to its corresponding hash output
	 * @param gamma Gamma point as bytes
	 * @returns Hash output as bytes
	 */
	private gammaToHash(gamma: Bytes): Bytes {
		const data = Buffer.concat([
			Buffer.from([this.suiteID]),
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT]),
			gamma,
			Buffer.from([this.PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK]),
		]);

		return sha256(data);
	}
}
