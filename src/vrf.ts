import * as elliptic from "elliptic";
import { AffinePoint, ENCODE_TO_CURVE_DST_BACK, ENCODE_TO_CURVE_DST_FRONT } from "./types";
import { newK256VRF } from "./utils";
import { BN } from "bn.js";
import { createHmac, createHash } from "crypto";
import { generateNonce } from "./nonce";

const EC = new elliptic.ec("secp256k1");

const suite_string = [0xfe]; //ECVRF-SECP256K1-SHA256-TAI
const SUITE_ID = Buffer.from(suite_string);
const vrfK256 = newK256VRF();


/**
 * EC.n = q
 * EC.g = B
 * x = private
 * Y = public
 * cofactor = 1
 *
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10.html#section-5.5
 */

const Hash = (...args: Buffer[]) => {
    const sha = createHash("sha256");
    for (const arg of args) sha.update(Buffer.from(arg));
    return sha.digest();
};

const HMAC = (secret: Buffer, ...args: Buffer[]) => {
    const hmac = createHmac("sha256", secret);
    for (const arg of args) hmac.update(Buffer.from(arg));
    return hmac.digest();
};

const Hex = (string: string | Buffer) => Buffer.from(string).toString("hex");

export function prove(secret: Buffer, message: Buffer): Buffer {
    // Step 1: derive public key from secret key as `Y = x * B`
    // @ts-ignore
    const publicKeyPoint = vrfK256.scalarBasePointMult(secret);
    // @ts-ignore
    const publicKeyBytes = publicKeyPoint.toBytes();

    // Step 2: Encode to curve (using TAI)
    // @ts-ignore
    const HPoint = vrfK256.encodeToCurveTAI(publicKeyBytes, message);
    // @ts-ignore
    const HBytes = HPoint.toBytes();

    // Step 4: Gamma = x * H
    // @ts-ignore
    const gammaPoint = vrfK256.scalarAffinePointMult(HPoint, secret);
    // @ts-ignore
    const gammaBytes = gammaPoint.toBytes();

    // Step 5: nonce (k generation)
    // @ts-ignore
    const kScalar = vrfK256.generateNonce(secret, HBytes);

    // Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
    // U = k*B
    // @ts-ignore
    const uPoint = vrfK256.scalarBasePointMult(kScalar);
    // @ts-ignore
    const uBytes = uPoint.toBytes();

    // @ts-ignore
    const vPoint = vrfK256.scalarAffinePointMult(HPoint, kScalar);
    // @ts-ignore
    const vBytes = vPoint.toBytes();

    // @ts-ignore
    const inputs = Buffer.concat([
        publicKeyBytes,
        HBytes,
        gammaBytes,
        uBytes,
        vBytes,
    ]);

    // @ts-ignore
    const cScalar = vrfK256.challengeGeneration(inputs, vrfK256.cLen);

    // Step 7: s = (k + c*x) mod q
    // @ts-ignore
    const mul = vrfK256.scalarMult(cScalar, secret);
    // @ts-ignore
    const sScalar = vrfK256.scalarAdd(mul, kScalar);

    // Step 8: encode (gamma, c, s)
    // @ts-ignore
    const result = Buffer.concat([
        gammaBytes,
        cScalar,
        sScalar,
    ]);

    return result;
};

const ECVRF_proof_to_hash = (pi_string: any) => {
    // @ts-ignore
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma] = D;
    const three_string = [0x03];
    const zero_string = [0x00];
    // @ts-ignore
    const gamma_string = point_to_string(Gamma);
    // @ts-ignore
    const beta_string = Hash(
        // @ts-ignore
        suite_string,
        three_string,
        gamma_string,
        zero_string
    );
    return beta_string;
};

const ECVRF_verify = (Y: any, pi_string: any, alpha_string: any) => {
    // @ts-ignore
    const y = EC.curve.decodePoint(Y, "hex");
    // @ts-ignore
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma, c, s] = D;
    // @ts-ignore
    const H = ECVRF_hash_to_curve(y, alpha_string);
    // @ts-ignore
    const U = /* B */ EC.g.mul(s).add(y.mul(c).neg());
    // @ts-ignore
    const V = H.mul(s).add(Gamma.mul(c).neg());
    // @ts-ignore
    const c_prime = ECVRF_hash_points(H, Gamma, U, V);
    return c.eq(c_prime)
        ? ["VALID", Hex(ECVRF_proof_to_hash(pi_string))]
        : ["INVALID", null];
};



const ECVRF_hash_to_curve_try_and_increment = (Y: any, alpha_string: any) => {
    let ctr = 0;
    // @ts-ignore
    const PK_string = point_to_string(Y);
    const one_string = [0x01];
    const zero_string = [0x00];
    let H = "INVALID";
    /**
     *   Draft10: While H is "INVALID" or H is the identity element of the elliptic
     *   curve group.
     *
     *   Draft04: While H is "INVALID" or H is EC point at infinity.
     *
     *   Note: identity element === point at infinity
     */
    // @ts-ignore
    while ((H == "INVALID" || H.isInfinity() || !is_on_curve(H)) && ctr < 256) {
        const ctr_string = [ctr];
        // @ts-ignore
        const hash_string = Hash(
            // @ts-ignore
            suite_string,
            one_string,
            PK_string,
            Buffer.from(alpha_string, "hex"),
            ctr_string,
            zero_string
        );
        // @ts-ignore
        H = arbitrary_string_to_point(hash_string);
        ctr++;
    }
    if (H == "INVALID") {
        throw new Error("hash_to_curve failed");
    }
    return H;
};

// https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
const ECVRF_nonce_generation_RFC6979 = (SK: any, h_string: any) => {
    // @ts-ignore
    const sk = zero_pad([...Buffer.from(SK, "hex")], 32);
    // @ts-ignore
    const h1 = zero_pad([...Buffer.from(Hash(h_string))], 32);
    let K = "0".repeat(64);
    let V = "1".repeat(64);
    // @ts-ignore
    K = HMAC(K, V, [0x00], sk, h1).toString("hex");
    // @ts-ignore
    V = HMAC(K, V).toString("hex");
    // @ts-ignore
    K = HMAC(K, V, [0x01], sk, h1).toString("hex");
    // @ts-ignore
    V = HMAC(K, V).toString("hex");
    // @ts-ignore
    V = HMAC(K, V).toString("hex"); // qLen = hLen = 32, skip loop
    // @ts-ignore
    return new BN(V, "hex");
};

// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
const int_to_string = (x: any, xLen: any) => {
    // @ts-ignore
    return x.toArray("be", xLen);
};

const is_on_curve = (point: any) => {
    // @ts-ignore
    const x = point.getX();
    // @ts-ignore
    const y = point.getY();

    if (x.isZero() || x.gte(EC.curve.p) || y.isZero() || y.gte(EC.curve.p)) {
        return false;
    }

    // @ts-ignore
    let lhs = y.mul(y).mod(EC.curve.p);
    // @ts-ignore
    let rhs = x.mul(x).mod(EC.curve.p).mul(x).mod(EC.curve.p);

    // @ts-ignore
    rhs = rhs.add(EC.curve.b).mod(EC.curve.p);
    // @ts-ignore
    return lhs.eq(rhs);
};

const string_to_point = (s: any) => {
    try {
        // @ts-ignore
        return EC.curve.decodePoint(s);
    } catch {
        return "INVALID";
    }
};

const point_to_string = (p: any) => {
    // @ts-ignore
    const prefix = new BN(2).add(p.getY().mod(new BN(2)));
    // @ts-ignore
    return [...prefix.toArray(), ...zero_pad(p.getX().toArray(), 32)];
};

const zero_pad = (p: any, qlen: any) =>
    // @ts-ignore
    [...new Array(qlen).fill(0), ...p].slice(-qlen);

const arbitrary_string_to_point = (s: any) => {
    if (s.length !== 32) {
        throw new Error("s should be 32 byte");
    }
    // @ts-ignore
    return string_to_point([0x02, ...s]);
};

const ECVRF_hash_points = (...points: any[]) => {
    const two_string = 0x02;
    // @ts-ignore
    const str = [...suite_string, two_string];
    // @ts-ignore
    const points_str = points.map((point) => point_to_string(point)).flat();
    str.push(...points_str);
    const zero_string = 0x0;
    str.push(zero_string);
    // @ts-ignore
    const c_string = Buffer.from(Hash(str));
    // @ts-ignore
    const truncated_c_string = c_string.slice(0, 16);
    // @ts-ignore
    const c = new BN(truncated_c_string);

    return c;
};

const ECVRF_decode_proof = (pi: any) => {
    const gamma_string = pi.slice(0, 66);
    const c_string = pi.slice(66, 66 + 32);
    const s_string = pi.slice(66 + 32, 66 + 32 + 64);

    // @ts-ignore
    const Gamma = string_to_point(Buffer.from(gamma_string, "hex"));

    if (Gamma === "INVALID") return "INVALID";

    // @ts-ignore
    const c = new BN(Buffer.from(c_string, "hex"));
    // @ts-ignore
    const s = new BN(Buffer.from(s_string, "hex"));

    // @ts-ignore
    if (s.gte(EC.n)) return "INVALID";

    return [Gamma, c, s];
};

const ECVRF_keygen = (entropy: any) => {
    // @ts-ignore
    const keypair = entropy ? EC.genKeyPair({ entropy }) : EC.genKeyPair();
    // @ts-ignore
    const secret_key = keypair.getPrivate("hex");
    // @ts-ignore
    const public_key = keypair.getPublic("hex");
    return {
        secret_key,
        public_key: {
            key: public_key,
            // @ts-ignore
            compressed: keypair.getPublic(true, "hex"),
            // @ts-ignore
            x: keypair.getPublic().getX(),
            // @ts-ignore
            y: keypair.getPublic().getY(),
        },
    };
};

const ECVRF_nonce_generation = ECVRF_nonce_generation_RFC6979;
const ECVRF_hash_to_curve = ECVRF_hash_to_curve_try_and_increment;

const getFastVerifyComponents = (Y: any, pi_string: any, alpha_string: any) => {
    // @ts-ignore
    const y = EC.curve.decodePoint(Y, "hex");
    // @ts-ignore
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma, c, s] = D;
    // @ts-ignore
    const H = ECVRF_hash_to_curve(y, alpha_string);
    // @ts-ignore
    const U = /* B */ EC.g.mul(s).add(y.mul(c).neg());
    // @ts-ignore
    const sH = H.mul(s);
    // @ts-ignore
    const cG = Gamma.mul(c);
    //[sHX, sHY, cGammaX, cGammaY]
    return {
        // @ts-ignore
        uX: U.x.toString(),
        // @ts-ignore
        uY: U.y.toString(),
        // @ts-ignore
        sHX: sH.x.toString(),
        // @ts-ignore
        sHY: sH.y.toString(),
        // @ts-ignore
        cGX: cG.x.toString(),
        // @ts-ignore
        cGY: cG.y.toString(),
    };
};

// module.exports.prove = ECVRF_prove;
// module.exports.verify = ECVRF_verify;
// module.exports.decode = ECVRF_decode_proof;
// module.exports.keygen = ECVRF_keygen;
// module.exports.getFastVerifyComponents = getFastVerifyComponents;
// module.exports.proofToHash = ECVRF_proof_to_hash;