/**
 * Parameters for a curve used in VRF
 */
export interface CurveParams {
	/** Curve name (as used by elliptic library) */
	name: string;
	/** Suite ID for the VRF */
	suiteID: number;
	/** Challenge length in bytes */
	cLen: number;
	/** Point length in bytes */
	ptLen: number;
	/** Hash algorithm to use */
	hashAlgorithm: string;
}

/**
 * Predefined curves for VRF
 */
export const CURVES: Record<string, CurveParams> = {
	secp256k1: {
		name: "secp256k1",

		suiteID: 0xfe, // ECVRF-SECP256K1-SHA256-TAI
		cLen: 16,
		ptLen: 32,
		hashAlgorithm: "sha256",
	},
	p256: {
		name: "p256",
		suiteID: 0x01, // ECVRF-P256-SHA256-TAI
		cLen: 16,
		ptLen: 32,
		hashAlgorithm: "sha256",
	},
};
