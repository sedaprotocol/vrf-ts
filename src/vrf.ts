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

const HMAC = (secret, ...args) => {
    const hmac = createHmac("sha256", secret);
    for (const arg of args) hmac.update(Buffer.from(arg));
    return hmac.digest();
};

const Hex = (string) => Buffer.from(string).toString("hex");

export const prove = (secret: Buffer, message: Buffer) => {
    // Step 1: derive public key from secret key as `Y = x * B`
    const publicKeyPoint = vrfK256.scalarBasePointMult(secret);
    const publicKeyBytes = publicKeyPoint.toBytes();

    // Step 2: Encode to curve (using TAI)
    const HPoint = vrfK256.encodeToCurveTAI(publicKeyBytes, message);
    const HBytes = HPoint.toBytes();

    // Step 4: Gamma = x * H
    const gammaPoint = vrfK256.scalarAffinePointMult(HPoint, secret);
    const gammaBytes = gammaPoint.toBytes();

    // Step 5: nonce (k generation)
    const digest = vrfK256.hash(gammaBytes);
    const kScalar = vrfK256.generateNonce(secret, digest);

    // Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
    // U = k*B
    const uPoint = vrfK256.scalarBasePointMult(kScalar);
    const uBytes = uPoint.toBytes();

    const vPoint = vrfK256.scalarAffinePointMult(HPoint, kScalar);
    const vBytes = vPoint.toBytes();

    const inputs = Buffer.concat([
        publicKeyBytes,
        HBytes,
        gammaBytes,
        uBytes,
        vBytes,
    ]);

    const cScalar = vrfK256.challengeGeneration(inputs, vrfK256.cLen);

    // Step 7: s = (k + c*x) mod q
    const mul = vrfK256.scalarMult(cScalar, secret);
    const sScalar = vrfK256.scalarAdd(mul, kScalar);

    // Step 8: encode (gamma, c, s)
    const result = Buffer.concat([
        gammaBytes,
        cScalar,
        sScalar,
    ]);

    return Hex(result);
};

const ECVRF_proof_to_hash = (pi_string) => {
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma] = D;
    const three_string = [0x03];
    const zero_string = [0x00];
    const gamma_string = point_to_string(Gamma);
    const beta_string = Hash(
        suite_string,
        three_string,
        gamma_string,
        zero_string
    );
    return beta_string;
};

const ECVRF_verify = (Y, pi_string, alpha_string) => {
    const y = EC.curve.decodePoint(Y, "hex");
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma, c, s] = D;
    const H = ECVRF_hash_to_curve(y, alpha_string);
    const U = /* B */ EC.g.mul(s).add(y.mul(c).neg());
    const V = H.mul(s).add(Gamma.mul(c).neg());
    const c_prime = ECVRF_hash_points(H, Gamma, U, V);
    return c.eq(c_prime)
        ? ["VALID", Hex(ECVRF_proof_to_hash(pi_string))]
        : ["INVALID", null];
};



const ECVRF_hash_to_curve_try_and_increment = (Y, alpha_string) => {
    let ctr = 0;
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
    while ((H == "INVALID" || H.isInfinity() || !is_on_curve(H)) && ctr < 256) {
        const ctr_string = [ctr];
        const hash_string = Hash(
            suite_string,
            one_string,
            PK_string,
            Buffer.from(alpha_string, "hex"),
            ctr_string,
            zero_string
        );
        H = arbitrary_string_to_point(hash_string);
        ctr++;
    }
    if (H == "INVALID") {
        throw new Error("hash_to_curve failed");
    }
    return H;
};

// https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
const ECVRF_nonce_generation_RFC6979 = (SK, h_string) => {
    const sk = zero_pad([...Buffer.from(SK, "hex")], 32);
    const h1 = zero_pad([...Buffer.from(Hash(h_string))], 32);
    let K = "0".repeat(64);
    let V = "1".repeat(64);
    K = HMAC(K, V, [0x00], sk, h1).toString("hex");
    V = HMAC(K, V).toString("hex");
    K = HMAC(K, V, [0x01], sk, h1).toString("hex");
    V = HMAC(K, V).toString("hex");
    V = HMAC(K, V).toString("hex"); // qLen = hLen = 32, skip loop
    return new BN(V, "hex");
};

// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
const int_to_string = (x, xLen) => {
    return x.toArray("be", xLen);
};

const is_on_curve = (point) => {
    const x = point.getX();
    const y = point.getY();

    if (x.isZero() || x.gte(EC.curve.p) || y.isZero() || y.gte(EC.curve.p)) {
        return false;
    }

    let lhs = y.mul(y).mod(EC.curve.p);
    let rhs = x.mul(x).mod(EC.curve.p).mul(x).mod(EC.curve.p);

    rhs = rhs.add(EC.curve.b).mod(EC.curve.p);
    return lhs.eq(rhs);
};

const string_to_point = (s) => {
    try {
        return EC.curve.decodePoint(s);
    } catch {
        return "INVALID";
    }
};

const point_to_string = (p) => {
    const prefix = new BN(2).add(p.getY().mod(new BN(2)));
    return [...prefix.toArray(), ...zero_pad(p.getX().toArray(), 32)];
};

const zero_pad = (p, qlen) => [...new Array(qlen).fill(0), ...p].slice(-qlen);

const arbitrary_string_to_point = (s) => {
    if (s.length !== 32) {
        throw new Error("s should be 32 byte");
    }
    return string_to_point([0x02, ...s]);
};

const ECVRF_hash_points = (...points) => {
    const two_string = 0x02;
    const str = [...suite_string, two_string];
    const points_str = points.map((point) => point_to_string(point)).flat();
    str.push(...points_str);
    const zero_string = 0x0;
    str.push(zero_string);
    const c_string = Buffer.from(Hash(str));
    const truncated_c_string = c_string.slice(0, 16);
    const c = new BN(truncated_c_string);

    return c;
};

const ECVRF_decode_proof = (pi) => {
    const gamma_string = pi.slice(0, 66);
    const c_string = pi.slice(66, 66 + 32);
    const s_string = pi.slice(66 + 32, 66 + 32 + 64);

    const Gamma = string_to_point(Buffer.from(gamma_string, "hex"));

    if (Gamma === "INVALID") return "INVALID";

    const c = new BN(Buffer.from(c_string, "hex"));
    const s = new BN(Buffer.from(s_string, "hex"));

    if (s.gte(EC.n)) return "INVALID";

    return [Gamma, c, s];
};

const ECVRF_keygen = (entropy) => {
    const keypair = entropy ? EC.genKeyPair({ entropy }) : EC.genKeyPair();
    const secret_key = keypair.getPrivate("hex");
    const public_key = keypair.getPublic("hex");
    return {
        secret_key,
        public_key: {
            key: public_key,
            compressed: keypair.getPublic(true, "hex"),
            x: keypair.getPublic().getX(),
            y: keypair.getPublic().getY(),
        },
    };
};

const ECVRF_nonce_generation = ECVRF_nonce_generation_RFC6979;
const ECVRF_hash_to_curve = ECVRF_hash_to_curve_try_and_increment;

const getFastVerifyComponents = (Y, pi_string, alpha_string) => {
    const y = EC.curve.decodePoint(Y, "hex");
    const D = ECVRF_decode_proof(pi_string);
    if (D == "INVALID") return D;
    const [Gamma, c, s] = D;
    const H = ECVRF_hash_to_curve(y, alpha_string);
    const U = /* B */ EC.g.mul(s).add(y.mul(c).neg());
    const sH = H.mul(s);
    const cG = Gamma.mul(c);
    //[sHX, sHY, cGammaX, cGammaY]
    return {
        uX: U.x.toString(),
        uY: U.y.toString(),
        sHX: sH.x.toString(),
        sHY: sH.y.toString(),
        cGX: cG.x.toString(),
        cGY: cG.y.toString(),
    };
};

// module.exports.prove = ECVRF_prove;
// module.exports.verify = ECVRF_verify;
// module.exports.decode = ECVRF_decode_proof;
// module.exports.keygen = ECVRF_keygen;
// module.exports.getFastVerifyComponents = getFastVerifyComponents;
// module.exports.proofToHash = ECVRF_proof_to_hash;