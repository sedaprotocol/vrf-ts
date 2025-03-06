import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import type { Bytes, PrivKey } from "@noble/secp256k1";

// Secp256k1 curve order (n)
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Generates a deterministic nonce (ephemeral scalar k) using RFC 6979.
 * @param secretKey The private key as bytes
 * @param digest The message digest
 * @returns The generated nonce as bytes
 */
export function generateNonce(secretKey: PrivKey, digest: Bytes): Bytes {
	// Convert secret key to bigint
	let x: bigint;

	if (typeof secretKey === "string") {
		// Handle hex string
		x = BigInt(`0x${secretKey.replace(/^0x/i, "")}`);
	} else if (typeof secretKey === "bigint") {
		// Handle bigint
		x = secretKey;
	} else {
		// Handle Uint8Array or Buffer
		x = bytesToBigInt(secretKey);
	}

	return generateSecret(SECP256K1_ORDER, x, digest);
}

/**
 * Implementation of RFC 6979 nonce generation
 * https://tools.ietf.org/html/rfc6979#section-3.2
 */
function generateSecret(order: bigint, x: bigint, digest: Bytes): Bytes {
	const qlen = bitLength(order);
	const holen = digest.length;
	const rolen = Math.ceil(qlen / 8);

	// Initial data
	const bx = Buffer.concat([int2octets(x, rolen), bits2octets(digest, order, qlen, rolen)]);

	// Step B
	let v: Bytes = Buffer.alloc(holen, 0x01);

	// Step C
	let k: Bytes = Buffer.alloc(holen, 0x00);

	// Step D
	k = hmac(sha256, k, Buffer.concat([v, Buffer.from([0x00]), bx]));

	// Step E
	v = hmac(sha256, k, v);

	// Step F
	k = hmac(sha256, k, Buffer.concat([v, Buffer.from([0x01]), bx]));

	// Step G
	v = hmac(sha256, k, v);

	// Step H
	while (true) {
		// Step H1
		let t = Buffer.alloc(0);

		// Step H2
		while (t.length < Math.ceil(qlen / 8)) {
			v = Buffer.from(hmac(sha256, k, v));
			t = Buffer.concat([t, v]);
		}

		// Step H3
		const secret = bits2int(t, qlen);
		if (secret > 0n && secret < order) {
			return int2octets(secret, rolen);
		}

		k = hmac(sha256, k, Buffer.concat([v, Buffer.from([0x00])]));
		v = hmac(sha256, k, v);
	}
}

/**
 * Convert bits to integer
 * https://tools.ietf.org/html/rfc6979#section-2.3.2
 */
function bits2int(bytes: Bytes, qlen: number): bigint {
	const vlen = bytes.length * 8;
	let v = bytesToBigInt(bytes);
	if (vlen > qlen) {
		v = v >> BigInt(vlen - qlen);
	}
	return v;
}

/**
 * Convert integer to octets
 * https://tools.ietf.org/html/rfc6979#section-2.3.3
 */
function int2octets(v: bigint, rolen: number): Bytes {
	const result = Buffer.alloc(rolen, 0);

	let tempV = v;
	for (let i = rolen - 1; i >= 0; i--) {
		result[i] = Number(tempV & 0xffn);
		tempV = tempV >> 8n;
	}

	return result;
}

/**
 * Convert bits to octets
 * https://tools.ietf.org/html/rfc6979#section-2.3.4
 */
function bits2octets(inp: Uint8Array, q: bigint, qlen: number, rolen: number): Bytes {
	const z1 = bits2int(inp, qlen);
	const z2 = z1 - q;

	if (z2 < 0n) {
		return int2octets(z1, rolen);
	}
	return int2octets(z2, rolen);
}

/**
 * Calculate bit length of a bigint
 */
function bitLength(n: bigint): number {
	return n.toString(2).length;
}

/**
 * Convert bytes to bigint
 */
function bytesToBigInt(bytes: Bytes): bigint {
	const hex = Buffer.from(bytes).toString("hex");
	return BigInt(`0x${hex}`);
}
