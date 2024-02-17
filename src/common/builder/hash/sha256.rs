use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::hash::traits::hasher::GenericCircuitMerkleHasher;
use crate::common::richer_field::RicherField;
use crate::common::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::common::u32::interleaved_u32::CircuitBuilderB32;

use super::hash256::{Hash256Target, CircuitBuilderHash};


pub trait CircuitBuilderHashSha256<F: RichField + Extendable<D>, const D: usize> {
    fn hash_sha256_u32(&mut self, data: &[U32Target]) -> Hash256Target;
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target;
}

/// Initial state for SHA-256.
#[rustfmt::skip]
pub const H256_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Constants necessary for SHA-256 family of digests.
#[rustfmt::skip]
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// (a rrot r1) xor (a rrot r2) xor (a rsh s3)
pub fn sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    s3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rsh_u32(a, s3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

// (a rrot r1) xor (a rrot r2) xor (a rrot r3)
pub fn big_sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    r3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rrot_u32(a, r3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

// (e and f) xor ((not e) and g)
pub fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    e: U32Target,
    f: U32Target,
    g: U32Target,
) -> U32Target {
    let not_e = builder.not_u32(e);

    let ef = builder.and_xor_u32(e, f).0;
    let eg = builder.and_xor_u32(not_e, g).0;

    builder.and_xor_b32_to_u32(ef, eg).1
}

// (a and b) xor (a and c) xor (b and c)
// = (a and (b xor c)) xor (b and c)
// we can calculate (b xor c), (b and c) in a single op
pub fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    b: U32Target,
    c: U32Target,
) -> U32Target {
    let (b_and_c, b_xor_c) = builder.and_xor_u32(b, c);

    let a = builder.interleave_u32(a);
    let abc = builder.and_xor_b32(a, b_xor_c).0;

    builder.and_xor_b32_to_u32(abc, b_and_c).1
}

pub fn sha256_start_state<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; 8] {
    [
        builder.constant_u32(H256_256[0]),
        builder.constant_u32(H256_256[1]),
        builder.constant_u32(H256_256[2]),
        builder.constant_u32(H256_256[3]),
        builder.constant_u32(H256_256[4]),
        builder.constant_u32(H256_256[5]),
        builder.constant_u32(H256_256[6]),
        builder.constant_u32(H256_256[7]),
    ]
}

pub fn sha256_round_constants<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; 64] {
    core::array::from_fn(|i| builder.constant_u32(K32[i]))
}

pub fn sha256_digest_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &mut [U32Target],
    block_data: &[U32Target],
    k256: &[U32Target],
) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    let mut w = [
        block_data[0],
        block_data[1],
        block_data[2],
        block_data[3],
        block_data[4],
        block_data[5],
        block_data[6],
        block_data[7],
        block_data[8],
        block_data[9],
        block_data[10],
        block_data[11],
        block_data[12],
        block_data[13],
        block_data[14],
        block_data[15],
    ];

    for i in 0..64 {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        if i >= 16 {
            let s0 = sigma(builder, w[(i + 1) & 0xf], 7, 18, 3);
            let s1 = sigma(builder, w[(i + 14) & 0xf], 17, 19, 10);
            w[i & 0xf] = builder
                .add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]])
                .0;
        }

        // Compression function main loop
        let big_s1_e = big_sigma(builder, e, 6, 11, 25);
        let ch_efg = ch(builder, e, f, g);
        let temp1 = builder
            .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
            .0;

        let big_s0_a = big_sigma(builder, a, 2, 13, 22);
        let maj_abc = maj(builder, a, b, c);
        let temp2 = builder.add_u32_lo(big_s0_a, maj_abc);

        h = g;
        g = f;
        f = e;
        e = builder.add_u32_lo(d, temp1);
        d = c;
        c = b;
        b = a;
        a = builder.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
    }

    // Add the compressed chunk to the current hash value
    state[0] = builder.add_u32_lo(state[0], a);
    state[1] = builder.add_u32_lo(state[1], b);
    state[2] = builder.add_u32_lo(state[2], c);
    state[3] = builder.add_u32_lo(state[3], d);
    state[4] = builder.add_u32_lo(state[4], e);
    state[5] = builder.add_u32_lo(state[5], f);
    state[6] = builder.add_u32_lo(state[6], g);
    state[7] = builder.add_u32_lo(state[7], h);
}

fn sha256_digest_u32_array<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    data: &[U32Target],
) -> Hash256Target {
    let mut state = sha256_start_state(builder);
    let round_constants = sha256_round_constants(builder);
    let standard_rounds = data.len() / 16;
    for i in 0..standard_rounds {
        sha256_digest_block(
            builder,
            &mut state,
            &data[i * 16..i * 16 + 16],
            &round_constants,
        );
    }
    let remaining = data.len() - standard_rounds * 16;
    let zero = builder.zero_u32();
    if remaining <= 13 {
        let mut block_data = [zero; 16];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }
        block_data[remaining] = builder.constant_u32(0x80000000);
        let len_bits = (data.len() as u64) * 32;
        block_data[14] = builder.constant_u32((len_bits >> 32) as u32);
        block_data[15] = builder.constant_u32((len_bits & 0xffffffff) as u32);

        sha256_digest_block(builder, &mut state, &block_data, &round_constants);
    } else {
        let mut block_data = [zero; 32];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }
        block_data[remaining] = builder.constant_u32(0x80000000);
        let len_bits = (data.len() as u64) * 32;
        block_data[30] = builder.constant_u32((len_bits >> 32) as u32);
        block_data[31] = builder.constant_u32((len_bits & 0xffffffff) as u32);
        sha256_digest_block(builder, &mut state, &block_data[0..16], &round_constants);
        sha256_digest_block(builder, &mut state, &block_data[16..32], &round_constants);
    }
    state
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashSha256<F, D>
    for CircuitBuilder<F, D>
{

    fn hash_sha256_u32(&mut self, data: &[U32Target]) -> Hash256Target {
        sha256_digest_u32_array(self, data)
    }

    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        let mut state: Hash256Target = [
            self.constant_u32(H256_256[0]),
            self.constant_u32(H256_256[1]),
            self.constant_u32(H256_256[2]),
            self.constant_u32(H256_256[3]),
            self.constant_u32(H256_256[4]),
            self.constant_u32(H256_256[5]),
            self.constant_u32(H256_256[6]),
            self.constant_u32(H256_256[7]),
        ];

        // Initialize array of round constants:
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        let k256 = sha256_round_constants(self);

        // Pre-processing (Padding)
        // Padding is done by the Witness when setting the input value to the target

        // block 1 data (left and right)
        let w: [U32Target; 16] = [
            left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7], right[0],
            right[1], right[2], right[3], right[4], right[5], right[6], right[7],
        ];
        // digest block 1
        sha256_digest_block(self, &mut state, &w, &k256);

        let zero = self.constant_u32(0);
        let cx80 = self.constant_u32(0x80000000);
        let c512 = self.constant_u32(512);

        // block 2 (padding/length in bits)
        let w: [U32Target; 16] = [
            cx80, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
            zero, c512,
        ];

        // digest block 2
        sha256_digest_block(self, &mut state, &w, &k256);
        state
    }
}

pub struct Sha256Hasher;
impl GenericCircuitMerkleHasher<Hash256Target> for Sha256Hasher{
    fn gc_two_to_one<F: RicherField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        builder.two_to_one_sha256(left, right)
    }

    fn two_to_one_swapped<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash256Target,
        right: Hash256Target,
        swap: BoolTarget,
    ) -> Hash256Target {
        let x = builder.select_hash256(swap, left, right);
        let y = builder.select_hash256(swap, right, left);
        Self::gc_two_to_one(builder, x, y)
    }

    fn two_to_one_swapped_marked_leaf<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash256Target,
        right: Hash256Target,
        swap: BoolTarget,
    ) -> Hash256Target {
        
        
        let x = builder.select_hash256(swap, left, right);
        let y = builder.select_hash256(swap, right, left);
        let preimage = [
            x[0],
            x[1],
            x[2],
            x[3],
            x[4],
            x[5],
            x[6],
            x[7],

            y[0],
            y[1],
            y[2],
            y[3],
            y[4],
            y[5],
            y[6],
            y[7],
            
            builder.one_u32(),
        ];
        builder.hash_sha256_u32(&preimage)
    }
}
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hex;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use crate::common::binaryhelpers::bytes::bytes_to_u32_vec_be;
    use crate::common::builder::hash::hash256::{CircuitBuilderHash, WitnessHash256};
    use crate::common::u32::arithmetic_u32::CircuitBuilderU32;
    use crate::common::u32::witness::WitnessU32;
    use super::CircuitBuilderHashSha256;
    use crate::common::base_types::hash::hash256::Hash256;

    #[test]
    fn test_sha256_two_to_one() {
        let tests = [
            [
                "44205ea3a71ee1cbd02eef7b084a409450c21d11a3b41769f02bb3e2dd89d5e2",
                "8ecf785b86dd1715d4c193f280a118b82200742f102bf1e59a4a65194a126f03",
                "a452e23aab1e4baae2e3da7c66da43954038e6505dc5b1cb24c8b5d95cf7634c",
            ],
            [
                "42f584ee07afb6754770ea07fc7f498cb7200ba89eb67361a7f2564612040cd3",
                "09e0ed078a0113619c033eec41b65e3168394dc377998bc13481b5f1942f7119",
                "2096622ca7f5aeda8d4c9a9cd4523e1bb9ea09e661f092f515c0c2cbaadcc2c6",
            ],
            [
                "8560e7d4c6e014b01b70bf5e1e2ffaa1e4115c9d21eb685b796b172872b71150",
                "3d38f5e8fc6c4612f27932b009bea0fd41a99c30af7a14a1e5316d9bbd5a4df6",
                "eab6fce22d0679c304d7419cf0746552921b31245d715171a5ec7c9caf81f084",
            ],
            [
                "7c909a4734e36fd67e11cd97a9a4222795672690f3eb081a2dd43a413ba6490c",
                "39a08a837c5bfef00ebb6e3b72f7fc5a8275f13fb5d5a86f03541ebf5ee8edec",
                "f537f1e2ac17a2af3524b7e3fc81ca88adcee65906236dab22250e071924e527",
            ],
            [
                "130151db7ac8036300c80c58a37de8119719ce60600b6e009d09df3a71d5f741",
                "a6bf923dbbcaae29701d82e0a1492ffe388aa14bd3e6ffbfa834aa9b23ad154a",
                "e70822e27d35acff57fc210d451aba171285025ac2fa77911e893427a8430b25",
            ],
            [
                "9992ff1b7ff438d5132b2b5ddd875c10ca62bcb46f681ef228548abdcd6db5c1",
                "4080eca86a5ea164518fc7426dc793ce5c9f95831bc8a97b2f06bc53722c78bb",
                "1bdbe0e67971989362b44c66f7ff26eea7d6c7f5f791d91e96bfa46a6934b97b",
            ],
            [
                "2a6f3577676eb6493d62268cf402f39f432490f8ca64d2323eab7ffb8fa5e239",
                "a004b81f69f9b6694fad09f0193e9120789d4e870681f436a97a2eef9089a3e2",
                "3dd8900540834a3fe28407796f128a21dd4c947b6b991ed14d6167ae4fc29cc3",
            ],
            [
                "7b4e5361bddc8029f76c3fead78e0a0a49e02dd40666cdff03ea40609de3c8d9",
                "bf7b76a80a3a70151640263f13bb62f72d66f0075f03b64e51aaec781b36d8c9",
                "809cf278ede0e210b29e7ce57b12a058d5d1f78be62a16df0c301995be7e7a5d",
            ],
            [
                "a52ae0c843df054f6a9489a743f293a74b7fe21f14bff5d35e9c9ec4fe336522",
                "e3e6379804432520b7eba2a7b46d0b016a4025f32da7cb8aa0003aaf57dab15c",
                "f56647e8f500efaafe8aaaf9a90b142685896cba145a06a6bc9853d9765079b8",
            ],
            [
                "386d9d8e6851f030ac2f510b6a8ebcc2f00e16a9cc7b7707d7d65f8a95ae82f3",
                "bb2b56422cd46210f5ab0c53527e8bf7ef71ad723a77a2cba0d990da15c9bde8",
                "d4d029cc7fbc6eba897d5659bb4d0298f9d3609c383526de67ab15b26fa95ad2",
            ],
            [
                "6e326b458d8bbef8b5a592e939d8bfa2dffb769a5f616034fb0cbf1267d4a600",
                "d5b60f7116771c9033a32bd2ccd22912d97bd3cf30d526fdcaff9f1bc9453397",
                "6c915b5095aca9df36491281c04a4f127b9fd81b4362742f07314d945b44582a",
            ],
            [
                "4af3eaf1108b48e0df66988876570f2044db09a0cad061da7d2448871fc52cb6",
                "cf5c4c57391fa60fbd613b2bdd5ddb5da9435239d073f2cdd265d0788e0b9cec",
                "54a342f852b7d41a5aab4a6a73cfc9adbc3b5fc42303627dbd604eede98e334f",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let left_target = builder.add_virtual_hash256_target();
        let right_target = builder.add_virtual_hash256_target();
        let expected_output_target = builder.add_virtual_hash256_target();
        let output_target = builder.two_to_one_sha256(left_target, right_target);
        builder.connect_hash256(output_target, expected_output_target);

        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "two_to_one_sha256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let left = Hash256::from_str(t[0]).unwrap();
            let right = Hash256::from_str(t[1]).unwrap();
            let expected_output = Hash256::from_str(t[2]).unwrap();

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_hash256_target(&left_target, &left.0);
            pw.set_hash256_target(&right_target, &right.0);
            pw.set_hash256_target(&expected_output_target, &expected_output.0);

            let start = Instant::now();
            let proof = data.prove(pw).unwrap();
            let end = start.elapsed();
            println!("two_to_one_sha256 proved in {}ms", end.as_millis());
            assert!(data.verify(proof).is_ok());
        }
    }

    #[test]
    fn test_sha256_long_arbitrary_length() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "9E05820FB000642E0F36AD7696F92D95C965CB27A8DC093D81A0D37B260A0F8E",
            ],
        ];
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let input = hex::decode(tests[0][0]).unwrap();
        let output = hex::decode(tests[0][1]).unwrap();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        println!("input len: {} (len/4 = {})", input.len(), input.len() / 4);

        let preimage_target = builder.add_virtual_u32_targets(input.len() / 4);
        println!("preimage target len {}", preimage_target.len());

        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output = builder.hash_sha256_u32(&preimage_target);
        builder.connect_hash256(hash_output, expected_output_target);

        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&input));
        pw.set_hash256_target(&expected_output_target, &output);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_sha256_arbitrary_length() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "9E05820FB000642E0F36AD7696F92D95C965CB27A8DC093D81A0D37B260A0F8E",
            ],
            [
                "3718CEB4122437AE80D343DFB857F4D016CA3072A05797AC24AE59918EA63C68CF97BD867F78455176EEE0709A9A59EF768E0C6D8A22BCD57ADBB3FB74A0A331F66D7E55CA3786E7C2AB91951F9A1C617CA32B34D395C745E8C15A90766735116E20A45ACA7E4BD37B7F46660E345415C758712EB9493B98C62CAD9B325B1927F7248B773E18D4E4B1D40675B3EFE7528914AD4BEDDB3BADBE05568AE539A6A308D4D2C453C726B34E84E5A6DDC5EED70026BDF5828B7A556342EFC1D8187A4BC7228D0654CB57BB",
                "E1B79FB8A21D1C1438C85BBC81250C112C3126E1935E1C8EF7B8880046B7604B",
            ],
            [
                "ea7f0fe7ed8b30b742b11a0052cd9a54aff18bd42598880371e19f080969270015cb21bc3e8fd66c50eac2d486e271a61313e60d8978caab7a1305725b8b8b20cec40ebef2ecec84efb3b034445f77e78a0630e62e90974a167ef05aead7bdf0cd1c82e34c3a0056befdffa8b75851a4ba7386ef5402ba5fbadace5026d9a0efc977b2f56d2a9f14573dae54f803895cd77571ad178c7aa0868bcf36704f2b5591b82f1ee5579872238930f3c0db7473484d416df0f800eb399bc73792bcab82273c8eb88d466972df36362839df6fe259bc07e1f7fe396fecf9b5a293edfe83211bb2904e629e9e9a01826a09512831abfeedca43e90e6662bbae159433781da39e4f57354c05d57d1ac8bf30cc53ca41bf518491c539fc848c41c7b6c0283468e9e091a190545d519fab7356b749e6b375b47d8dc8e2b1950ecc8139567e1681a6b8226c915de59669555e08c84adc6d292dd5f191f55496ea114c7e7a03ed1a0ca987cb65788613b21be8aa42556e9fbd2567f9a34f6dcff9546e427a91cfb81c2b7cc9ffd1dfc33829336882c4044b0599f0b1cca0cabe26775d37afa787ff1909aa4e78fe0f0b038a42ed5169e5baa44ea9ce0b45aeebea122d850c5d233f10d29ec1c93945e2683c3e9f7eb9054b1f276a0f876f8945c6ebcb714fd8f1a9f3ebe497032e3fa80d2ac9e7e7d7058b705c8889295d084f6108438334deeae670c71d0b57a90cc3e58dc03183f5b9864c5f804a16a91138670360c21391cddc9ac722c6afc3a0f58e59d97ebe8f09a2a68fc265e785bff8aa2bb175a3f4d027a10ee517576f4d4d573eb4f21c8a2d722e1e26780574ed971358a4f1909337b425aef68b3ccd8babf9b7df0bd0759aff72a92462954ee533e9c81cf44e6924cda97a5ce99712c5c1a269a9b5782df41322411f9bbc0ac2e09be861f5b2f1dedfda3082f85202d322814961a29d823a69fc2d539d1fda42559a9e800de3a58432be2c863687febbf4f76f2be30953a72ca02e02eb210feb633dfd6c80cee0638e9de2e8fc02bcc7b341e0964fa76db41de5329a68d29f26ab438ebbd2affb94b462da35653c3bff571e9356208d6c046eb2941623c61788e3e0ab75660bcc72d6d6b7f68aaead8832f81d8e4dd260f1f6ee6f6f6a0985cd2d83c6f97bfe9f9a548c542f8a2b33e48e6c15ff51563167640129eac1013836d6524bfb8c28e18a7201396458256135677cd25b4e0507d61687617126f2baaf3fe36e55d1de27fd9b07a8e90220eebf511978f962c2eb17112f108e958c36c1969b66fff85b5d8c77fc2f6f2d9e0cead09db62cd94a1aff9f9b3438a934dbb99d6f2b4b4bc0bdd50b2cc0ddb88e65e1b21cabe4b7ea3ff4620ba40dc7d5656a7c412fff72326cf666d0555d6470f6de",
                "D1FD0A9EA4D65D43C584C3845A90078EA0CDE6566459756DCDE50F9875E7A95A"
            ]
        ];
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        for t in tests {
            // build circuit for each test
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let preimage_target = builder.add_virtual_u32_targets(input.len() / 4);
            let expected_output_target = builder.add_virtual_hash256_target();

            let hash_output = builder.hash_sha256_u32(&preimage_target);
            builder.connect_hash256(hash_output, expected_output_target);

            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
                input.len(),
                num_gates,
                data.common.quotient_degree_factor
            );
            let mut pw = PartialWitness::new();
            pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&input));
            pw.set_hash256_target(&expected_output_target, &output);

            let start_time = std::time::Instant::now();
            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);

            assert!(data.verify(proof).is_ok());
        }
    }
}
