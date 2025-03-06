import type { Bytes, Hex, PrivKey } from "@noble/secp256k1";

export type { Bytes, Hex, PrivKey };

export declare class Secp256k1Vrf {
	/**
	 * Generate a VRF proof for a message using a private key
	 * @param secret Private key as bytes
	 * @param message Message to prove as bytes
	 * @returns VRF proof as bytes
	 */
	prove(secret: PrivKey, message: Bytes): Bytes;

	/**
	 * Verify a VRF proof and return the resulting hash if valid
	 * @param publicKey Public key as bytes
	 * @param proof VRF proof as bytes
	 * @param message Original message as bytes
	 * @returns Hash as a hex string if valid, "INVALID" if invalid
	 */
	verify(publicKey: Hex, proof: Bytes, message: Bytes): string;

	/**
	 * Convert a VRF proof to its corresponding hash output
	 * @param proof VRF proof as bytes
	 * @returns Hash output as a hex string
	 */
	proofToHash(proof: Bytes): string;

	/**
	 * Generate a key pair for use with VRF
	 * @returns Object containing secret key and public key as hex strings
	 */
	keygen(): {
		secretKey: string;
		publicKey: string;
	};
}
