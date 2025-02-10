import BN from 'bn.js';
import { createHmac } from 'crypto';

/**
 * Generates a deterministic nonce (ephemeral scalar k) using RFC 6979.
 * @param q The order of the curve
 * @param secretKey The private key as bytes
 * @param digest The message digest
 * @returns The generated nonce as bytes
 */
export function generateNonce(q: BN, secretKey: Buffer, digest: Buffer): Buffer {
    // Convert secret key to BN and generate nonce
    const x = new BN(secretKey);
    return generateSecret(q, x, digest);
}

/**
 * Implementation of RFC 6979 nonce generation
 * https://tools.ietf.org/html/rfc6979#section-3.2
 */
function generateSecret(q: BN, x: BN, digest: Buffer): Buffer {
    const qlen = q.bitLength();
    const holen = 32; // SHA256 size
    const rolen = Math.ceil(qlen / 8);

    // Initial data
    const bx = Buffer.concat([
        int2octets(x, rolen),
        bits2octets(digest, q, qlen, rolen)
    ]);

    // Step B
    // @ts-ignore
    let v = Buffer.alloc(holen, 0x01);

    // Step C
    // @ts-ignore
    let k = Buffer.alloc(holen, 0x00);

    // Step D
    // @ts-ignore
    k = mac(k, Buffer.concat([v, Buffer.from([0x00]), bx]));

    // Step E
    // @ts-ignore
    v = mac(k, v);

    // Step F
    // @ts-ignore
    k = mac(k, Buffer.concat([v, Buffer.from([0x01]), bx]));

    // Step G
    // @ts-ignore
    v = mac(k, v);

    // Step H
    const one = new BN(1);
    while (true) {
        // Step H1
        let t = Buffer.alloc(0);

        // Step H2
        while (t.length < Math.ceil(qlen / 8)) {
            // @ts-ignore
            v = mac(k, v);
            t = Buffer.concat([t, v]);
        }

        // Step H3
        const secret = bits2int(t, qlen);
        if (secret.gte(one) && secret.lt(q)) {
            return t;
        }

        // @ts-ignore
        k = mac(k, Buffer.concat([v, Buffer.from([0x00])]));
        // @ts-ignore
        v = mac(k, v);
    }
}

/**
 * HMAC using SHA256
 */
function mac(key: Buffer, msg: Buffer): Buffer {
    const h = createHmac('sha256', key);
    h.update(msg);
    return h.digest();
}

/**
 * Convert bits to integer
 * https://tools.ietf.org/html/rfc6979#section-2.3.2
 */
function bits2int(bytes: Buffer, qlen: number): BN {
    const vlen = bytes.length * 8;
    let v = new BN(bytes);
    if (vlen > qlen) {
        v = v.shrn(vlen - qlen);
    }
    return v;
}

/**
 * Convert integer to octets
 * https://tools.ietf.org/html/rfc6979#section-2.3.3
 */
function int2octets(v: BN, rolen: number): Buffer {
    let out = Buffer.from(v.toArray());

    // Pad with zeros if too short
    if (out.length < rolen) {
        const out2 = Buffer.alloc(rolen, 0);
        out.copy(out2, rolen - out.length);
        return out2;
    }

    // Drop most significant bytes if too long
    if (out.length > rolen) {
        const out2 = Buffer.alloc(rolen);
        out.copy(out2, 0, out.length - rolen);
        return out2;
    }

    return out;
}

/**
 * Convert bits to octets
 * https://tools.ietf.org/html/rfc6979#section-2.3.4
 */
function bits2octets(inp: Buffer, q: BN, qlen: number, rolen: number): Buffer {
    const z1 = bits2int(inp, qlen);
    const z2 = z1.sub(q);
    
    if (z2.isNeg()) {
        return int2octets(z1, rolen);
    }
    return int2octets(z2, rolen);
}
