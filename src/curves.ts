/**
 * Parameters for a curve used in VRF
 */
export interface CurveParams {
	/** Curve name (as used by elliptic library) */
	name: string;
	/** Full suite name (e.g., "ECVRF-P256-SHA256-TAI") */
	suiteName: string;
	/** Suite ID for the VRF */
	suiteID: number;
	/** Challenge length in bytes (per RFC 9381 Section 5.3) */
	cLen: number;
	/** Coordinate length in bytes (x/y coordinate size, total point size will be this + 1 for compressed format) */
	ptLen: number;
	/** Hash algorithm to use */
	hashAlgorithm: string;
	/** Cofactor of the curve */
	cofactor: number;
}

/**
 * Enum for Suite IDs
 */
enum SuiteID {
	/**
	 * Extension beyond RFC 9381 - secp256k1 with SHA-256 and TAI
	 * Note: This is not defined in RFC 9381 and is a custom extension
	 */
	ECVRF_SECP256K1_SHA256_TAI = 0xfe,

	/** ECVRF-P256-SHA256-TAI as defined in RFC 9381 Section 5.5 */
	ECVRF_P256_SHA256_TAI = 0x01,

	/** ECVRF-P256-SHA512-TAI as defined in RFC 9381 (but not implemented here) */
	ECVRF_P256_SHA512_TAI = 0x02,

	/** ECVRF-EDWARDS25519-SHA512-TAI as defined in RFC 9381 (but not implemented here) */
	ECVRF_EDWARDS25519_SHA512_TAI = 0x03,
}

export type VrfTypes = "secp256k1-sha256-tai" | "p256-sha256-tai" | "secp256k1" | "p256";

type PartialRecord<K extends keyof any, T> = {
	[P in K]?: T;
};

/**
 * Predefined curves for VRF
 */
const PREDEFINED_CURVES: PartialRecord<VrfTypes, CurveParams> = {
	/**
	 * secp256k1 curve with SHA-256 and TAI encoding (extension beyond RFC 9381)
	 */
	"secp256k1-sha256-tai": {
		name: "secp256k1",
		suiteName: "ECVRF-SECP256K1-SHA256-TAI",
		suiteID: SuiteID.ECVRF_SECP256K1_SHA256_TAI,
		cLen: 16, // Using 16 bytes for consistency with P-256 suite
		ptLen: 32, // Coordinate length (x/y) - compressed point will be 33 bytes total
		hashAlgorithm: "sha256",
		cofactor: 1,
	},

	/**
	 * NIST P-256 curve with SHA-256 and TAI encoding
	 * Implements ECVRF-P256-SHA256-TAI as defined in RFC 9381 Section 5.5
	 */
	"p256-sha256-tai": {
		name: "p256",
		suiteName: "ECVRF-P256-SHA256-TAI",
		suiteID: SuiteID.ECVRF_P256_SHA256_TAI,
		cLen: 16, // Per RFC 9381 Section 5.3: secParam/2 = 128/8 = 16 bytes
		ptLen: 32, // Coordinate length (x/y) - compressed point will be 33 bytes total
		hashAlgorithm: "sha256",
		cofactor: 1,
	},
};

// For backward compatibility, add aliases with old names
export const CURVES: PartialRecord<VrfTypes, CurveParams> = {
	secp256k1: PREDEFINED_CURVES["secp256k1-sha256-tai"],
	p256: PREDEFINED_CURVES["p256-sha256-tai"],
	...PREDEFINED_CURVES,
};

// Export SuiteID for external use
export { SuiteID };
