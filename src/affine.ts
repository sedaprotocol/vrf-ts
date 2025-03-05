import type BN from "bn.js";
import type elliptic from "elliptic";

export class AffinePoint {
	private curve: elliptic.ec;

	constructor(
		public x: BN,
		public y: BN,
		curve: elliptic.ec,
	) {
		this.curve = curve;
	}

	toObject() {
		return {
			x: BigInt(this.x.toString()),
			y: BigInt(this.y.toString()),
		};
	}

	/**
	 * Parse a compressed public key into an AffinePoint
	 */
	static fromBytes(data: Buffer, curve: elliptic.ec): AffinePoint {
		// Different curves may have different compressed point sizes
		// For secp256k1, it's 33 bytes (1 byte prefix + 32 bytes for x coordinate)

		try {
			const point = curve.keyFromPublic(data);
			if (!point) {
				throw new Error("Failed to unmarshal bytes to an elliptic curve point");
			}
			return new AffinePoint(point.getPublic().getX(), point.getPublic().getY(), curve);
		} catch (error: unknown) {
			const errorMessage = error instanceof Error ? error.message : String(error);
			throw new Error(`Invalid point format for the specified curve: ${errorMessage}`);
		}
	}

	/**
	 * Convert the point to compressed SEC1 format
	 */
	toBytes(): Buffer {
		try {
			// @ts-ignore
			const p = this.curve.keyFromPublic({ x: this.x.toBuffer(), y: this.y.toBuffer() });
			return Buffer.from(p.getPublic(true, "hex"), "hex");
		} catch (error: unknown) {
			const errorMessage = error instanceof Error ? error.message : String(error);
			throw new Error(`Failed to convert point to bytes: ${errorMessage}`);
		}
	}
}
