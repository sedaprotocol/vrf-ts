import { ECVRF_prove } from "./src/vrf";

const proof = ECVRF_prove(Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex"), Buffer.from("73616d706c65", "hex"));

console.log('[DEBUG]: proof ::: ', proof);