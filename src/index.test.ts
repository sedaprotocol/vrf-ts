import { describe, expect, test } from "bun:test";
import { VRF } from "./vrf";

describe("VRF", () => {
	test("Secp256k1 matches test vectors", async () => {
		const secp256k1TestVectors = require("../test-vectors/ECVRF_secp256k1_SHA256_TAI.json");
		const vrf = new VRF("secp256k1");

		for (const vector of secp256k1TestVectors) {
			const privateKey = Buffer.from(vector.priv, "hex");
			const message = Buffer.from(vector.message, "hex");
			const publicKey = Buffer.from(vector.pub, "hex");
			const expectedProof = vector.pi.toLowerCase();
			const expectedHash = vector.hash.toLowerCase();

			// Test proof generation
			const proof = vrf.prove(privateKey, message);
			expect(proof.toString("hex")).toBe(expectedProof);

			// Test proof verification
			const hash = vrf.verify(publicKey, proof, message);
			expect(hash).toBe(expectedHash);

			// Test proof to hash conversion
			const proofHash = vrf.proofToHash(proof);
			expect(proofHash).toBe(expectedHash);
		}
	});

	test("P256 matches test vectors", async () => {
		const p256TestVectors = require("../test-vectors/ECVRF_P256_SHA256_TAI.json");

		const vrf = new VRF("p256");

		for (const vector of p256TestVectors) {
			const privateKey = Buffer.from(vector.priv, "hex");
			const message = Buffer.from(vector.message, "hex");
			const publicKey = Buffer.from(vector.pub, "hex");
			const expectedProof = vector.pi.toLowerCase();
			const expectedHash = vector.hash.toLowerCase();

			// Test proof generation
			const proof = vrf.prove(privateKey, message);
			expect(proof.toString("hex")).toBe(expectedProof);

			// Test proof verification
			const hash = vrf.verify(publicKey, proof, message);
			expect(hash).toBe(expectedHash);

			// Test proof to hash conversion
			const proofHash = vrf.proofToHash(proof);
			expect(proofHash).toBe(expectedHash);
		}
	});
});
