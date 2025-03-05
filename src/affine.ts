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
		// Get the field size in bytes (for x coordinate)
		const fieldSize = Math.ceil(curve.curve.p.bitLength() / 8);

		// Expected size: 1 byte prefix + field size bytes for x coordinate
		const expectedSize = fieldSize + 1;

		if (data.length !== expectedSize) {
			throw new Error(
				`Invalid point size: expected ${expectedSize} bytes (1 byte prefix + ${fieldSize} bytes for x coordinate), got ${data.length} bytes`,
			);
		}

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

	/**
	 * Multiply this point by a scalar
	 * @param scalar The scalar to multiply by
	 * @returns A new AffinePoint representing the result
	 */
	multiply(scalar: BN): AffinePoint {
		// Convert to elliptic.js point format
		const point = this.curve.curve.point(this.x, this.y);

		// Perform multiplication
		const result = point.mul(scalar);

		// Convert back to AffinePoint
		return new AffinePoint(result.getX(), result.getY(), this.curve);
	}
}
