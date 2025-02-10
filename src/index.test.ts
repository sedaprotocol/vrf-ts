import { expect, test, describe } from "bun:test";
import * as vrf from "./vrf";
import testVectors from "./ECVRF_SECP256K1_SHA256_TAI.json";

describe("VRF", () => {
  test("matches test vectors", async () => {
    // const vrf = new VRF();

    for (const vector of testVectors) {
      const privateKey = Buffer.from(vector.priv, 'hex');
      const message = Buffer.from(vector.message, 'hex');
      const publicKey = Buffer.from(vector.pub, 'hex');
      const expectedProof = vector.pi.toLowerCase();
      const expectedHash = vector.hash.toLowerCase();

      // Test proof generation
      const proof = vrf.prove(privateKey, message);
      expect(proof.toString('hex')).toBe(expectedProof);

    //   // Test proof verification
    //   const hash = await vrf.verify(publicKey, proof, message);
    //   expect(hash.toString('hex')).toBe(expectedHash);

    //   // Test proof to hash conversion
    //   const proofHash = await vrf.proofToHash(proof);
    //   expect(proofHash.toString('hex')).toBe(expectedHash);
    }
  });
});
