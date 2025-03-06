import { describe, expect, test } from "bun:test";
import { Secp256k1Vrf } from "./secp256k1-vrf";

describe("VRF", () => {
	test("Secp256k1Vrf matches test vectors", async () => {
		const secp256k1TestVectors = require("../test-vectors/ECVRF_secp256k1_SHA256_TAI.json");
		const vrf = new Secp256k1Vrf();

		// Test all vectors
		for (const vector of secp256k1TestVectors) {
			const privateKey = Buffer.from(vector.priv, "hex");
			const message = Buffer.from(vector.message, "hex");
			const publicKey = Buffer.from(vector.pub, "hex");
			const expectedProof = vector.pi.toLowerCase();
			const expectedHash = vector.hash.toLowerCase();

			// Test proof generation
			const proof = vrf.prove(privateKey, message);
			expect(Buffer.from(proof).toString("hex")).toBe(expectedProof);

			// Test proof verification
			const hash = vrf.verify(publicKey, proof, message);
			expect(hash).toBe(expectedHash);

			// Test proof to hash conversion
			const proofHash = vrf.proofToHash(proof);
			expect(proofHash).toBe(expectedHash);
		}
	});
});
