use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::builder::hash::hash256::CircuitBuilderHash;
use crate::common::hash::traits::hasher::GenericCircuitMerkleHasher;
use crate::common::richer_field::RicherField;
use crate::common::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::common::u32::interleaved_u32::CircuitBuilderB32;

use super::hash256::Hash256Target;

pub trait CircuitBuilderHashBlake3<F: RichField + Extendable<D>, const D: usize> {
    fn hash_blake3_u32(&mut self, data: &[U32Target]) -> Hash256Target;
    fn two_to_one_blake3(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target;
    
    fn hash_blake3_u32_with_key(&mut self, data: &[U32Target], key: &[u8]) -> Hash256Target;
    fn two_to_one_blake3_with_key(
        &mut self,
        left: Hash256Target,
        right: Hash256Target,
        key: &[u8],
    ) -> Hash256Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashBlake3<F, D>
    for CircuitBuilder<F, D>
{
    fn hash_blake3_u32(&mut self, data: &[U32Target]) -> Hash256Target {
        let mut b3 = Blake3::create(self);
        b3.update(self, data);
        b3.digest(self)
    }

    fn two_to_one_blake3(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        println!("two_to_one_blake3");
        self.hash_blake3_u32(&[left, right].concat())
    }

    fn hash_blake3_u32_with_key(&mut self, data: &[U32Target], key: &[u8]) -> Hash256Target {
        let mut b3 = Blake3::create_with_key_u8(self, key);
        b3.update(self, data);
        b3.digest(self)
    }

    fn two_to_one_blake3_with_key(
        &mut self,
        left: Hash256Target,
        right: Hash256Target,
        key: &[u8],
    ) -> Hash256Target {
        self.hash_blake3_u32_with_key(&[left, right].concat(), key)
    }
}

/// IV for blake3
#[rustfmt::skip]
pub const BLAKE3_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
// Permutation for Blake3
#[rustfmt::skip]
pub const BLAKE3_MESSAGE_PERMUTATION: [usize; 16] = [
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
];
const BLAKE3_BLOCK_LEN: usize = 64;
const BLAKE3_CHUNK_LEN: usize = 1024;
const BLAKE3_CHUNK_START: u32 = 1;
const BLAKE3_CHUNK_END: u32 = 2;
const BLAKE3_PARENT: u32 = 4;
const BLAKE3_ROOT: u32 = 8;
const BLAKE3_KEYED_HASH: u32 = 16;

fn xor_rot_right<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    b: U32Target,
    rot: u8,
) -> U32Target {
    let x = builder.xor_u32(a, b);
    builder.rrot_u32(x, rot)
}
fn add_3<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    b: U32Target,
    c: U32Target,
) -> U32Target {
    let tmp = builder.add_u32_lo(a, b);
    builder.add_u32_lo(tmp, c)
}
pub fn blake3_g<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &mut [U32Target; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: U32Target,
    my: U32Target,
) {
    println!("blake3_g");
    state[a] = add_3(builder, state[a], state[b], mx);
    state[d] = xor_rot_right(builder, state[d], state[a], 16);
    state[c] = builder.add_u32_lo(state[c], state[d]);
    state[b] = xor_rot_right(builder, state[b], state[c], 12);
    state[a] = add_3(builder, state[a], state[b], my);
    state[d] = xor_rot_right(builder, state[d], state[a], 8);
    state[c] = builder.add_u32_lo(state[c], state[d]);
    state[b] = xor_rot_right(builder, state[b], state[c], 7);
}
pub fn blake3_round<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &mut [U32Target; 16],
    m: &[U32Target],
) {
    // Mix columns
    blake3_g(builder, state, 0, 4, 8, 12, m[0], m[1]);
    blake3_g(builder, state, 1, 5, 9, 13, m[2], m[3]);
    blake3_g(builder, state, 2, 6, 10, 14, m[4], m[5]);
    blake3_g(builder, state, 3, 7, 11, 15, m[6], m[7]);

    // Mix diagonals
    blake3_g(builder, state, 0, 5, 10, 15, m[8], m[9]);
    blake3_g(builder, state, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(builder, state, 2, 7, 8, 13, m[12], m[13]);
    blake3_g(builder, state, 3, 4, 9, 14, m[14], m[15]);
}
fn blake3_permute(block_words: &[U32Target]) -> [U32Target; 16] {
    core::array::from_fn(|i| block_words[BLAKE3_MESSAGE_PERMUTATION[i]])
}
pub fn blake3_compress<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chaining_value: &[U32Target],
    block_words: &[U32Target],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [U32Target; 16] {
    let compress_constants = [
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];

    let state_constants: [U32Target; 8] =
        core::array::from_fn(|i| builder.constant_u32(compress_constants[i]));

    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        state_constants[0],
        state_constants[1],
        state_constants[2],
        state_constants[3],
        state_constants[4],
        state_constants[5],
        state_constants[6],
        state_constants[7],
    ];

    blake3_round(builder, &mut state, block_words);
    let mut bws = blake3_permute(block_words);
    for _ in 2..=7 {
        blake3_round(builder, &mut state, &bws);
        bws = blake3_permute(&bws);
    }

    for i in 0..8 {
        state[i] = builder.xor_u32(state[i], state[i + 8]);
        state[i + 8] = builder.xor_u32(state[i + 8], chaining_value[i]);
    }
    state
}
pub fn blake3_compress_8<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chaining_value: &[U32Target],
    block_words: &[U32Target],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [U32Target; 8] {
    let output = blake3_compress(
        builder,
        chaining_value,
        block_words,
        counter,
        block_len,
        flags,
    );
    [
        output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7],
    ]
}
pub struct B3Node {
    pub input_chaining_value: [U32Target; 8],
    pub block_words: [U32Target; 16],
    pub counter: u64,
    pub block_len: u32,
    pub flags: u32,
}
impl B3Node {
    pub fn chaining_value<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> [U32Target; 8] {
        blake3_compress_8(
            builder,
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )
    }
    pub fn root_output_bytes<
        F: RichField + Extendable<D>,
        const D: usize,
        const OUTPUTS_LEN: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> [U32Target; OUTPUTS_LEN] {
        let mut output_counter = 0;
        const COMPRESS_U32_OUTPUT_SIZE: usize = 16;
        let outputs_needed = OUTPUTS_LEN / COMPRESS_U32_OUTPUT_SIZE + 1;
        let zero = builder.zero_u32();
        let mut hash = [zero; OUTPUTS_LEN];

        while output_counter < outputs_needed {
            let words = blake3_compress(
                builder,
                &self.input_chaining_value,
                &self.block_words,
                output_counter as u64,
                self.block_len,
                self.flags | BLAKE3_ROOT,
            );
            let cur_base_ind = output_counter * COMPRESS_U32_OUTPUT_SIZE;
            if (output_counter + 1) == outputs_needed {
                for i in 0..(OUTPUTS_LEN - cur_base_ind) {
                    hash[cur_base_ind + i] = words[i];
                }
            } else {
                for i in 0..COMPRESS_U32_OUTPUT_SIZE {
                    hash[cur_base_ind + i] = words[i];
                }
            }
            output_counter += 1;
        }
        hash
    }
}
pub struct ChunkState {
    pub block: [U32Target; 16],
    pub block_len: usize,
    pub blocks_compressed: usize,
    pub chaining_value: [U32Target; 8],
    pub chunk_counter: u64,
    pub flags: u32,
}
impl ChunkState {
    pub fn len(&self) -> usize {
        self.blocks_compressed * BLAKE3_BLOCK_LEN + self.block_len
    }
    pub fn update<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        input: &[U32Target],
    ) {
        let mut curr_pos = 0;
        while curr_pos < (input.len() * 4) {
            if self.block_len == BLAKE3_BLOCK_LEN {
                self.chaining_value = blake3_compress_8(
                    builder,
                    &self.chaining_value,
                    &self.block,
                    self.chunk_counter,
                    BLAKE3_BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.blocks_compressed += 1;
                self.block = [builder.zero_u32(); 16];
                self.block_len = 0;
            }
            let want = BLAKE3_BLOCK_LEN - self.block_len;
            let can_take = std::cmp::min(want, 4 * input.len() - curr_pos);
            for i in 0..(can_take / 4) {
                self.block[(self.block_len / 4) + i] = input[(curr_pos / 4) + i];
            }
            self.block_len += can_take;
            curr_pos += can_take;
        }
    }
    pub fn create_node(&self) -> B3Node {
        B3Node {
            input_chaining_value: self.chaining_value,
            block_words: self.block,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | BLAKE3_CHUNK_END,
        }
    }
    pub fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            BLAKE3_CHUNK_START
        } else {
            0
        }
    }
}

pub struct Blake3 {
    pub chunk_state: ChunkState,
    pub cv_stack: Vec<[U32Target; 8]>,
    pub cv_stack_len: usize,
    pub flags: u32,
    pub key: [U32Target; 8],
}
impl Blake3 {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        key: [u32; 8],
        flags: u32,
    ) -> Self {
        let chaining_value: [U32Target; 8] = core::array::from_fn(|i| builder.constant_u32(key[i]));

        Self {
            chunk_state: ChunkState {
                block: [builder.zero_u32(); 16],
                block_len: 0,
                blocks_compressed: 0,
                chaining_value: chaining_value.clone(),
                chunk_counter: 0,
                flags,
            },
            cv_stack: Vec::new(),
            cv_stack_len: 0,
            flags,
            key: chaining_value,
        }
    }

    pub fn create<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::new(builder, BLAKE3_IV, 0)
    }
    pub fn create_with_key<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        key: [u32; 8],
    ) -> Self {
        Self::new(builder, key, BLAKE3_KEYED_HASH)
    }
    pub fn create_with_key_u8<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        key: &[u8],
    ) -> Self {
        let mut key_u32 = [0u32; 8];
        for i in 0..key.len() {
            key_u32[i / 4] |= (key[i] as u32) << ((i & 3) * 8);
        }
        Self::new(builder, key_u32, BLAKE3_KEYED_HASH)
    }

    pub fn update<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        input: &[U32Target],
    ) {
        let mut curr_pos = 0;
        while curr_pos < (input.len() * 4) {
            // If this chunk has chained in 16 64 bytes of input, add its CV to the stack
            if self.chunk_state.len() == BLAKE3_CHUNK_LEN {
                let chunk_cv = self.chunk_state.create_node().chaining_value(builder);
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(builder, chunk_cv, total_chunks);
                self.chunk_state = ChunkState {
                    block: [builder.zero_u32(); 16],
                    block_len: 0,
                    blocks_compressed: 0,
                    chaining_value: self.key,
                    chunk_counter: total_chunks,
                    flags: self.flags,
                };
            }
            let want = BLAKE3_CHUNK_LEN - self.chunk_state.len();
            let can_take = std::cmp::min(want, 4 * input.len() - curr_pos);
            self.chunk_state.update(
                builder,
                &input[(curr_pos / 4)..(curr_pos / 4 + can_take / 4)],
            );
            curr_pos += can_take;
        }
    }
    pub fn parent_node<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left_child_cv: [U32Target; 8],
        right_child_cv: [U32Target; 8],
        key: [U32Target; 8],
        flags: u32,
    ) -> B3Node {
        let mut block_words = [builder.zero_u32(); 16];
        for i in 0..8 {
            block_words[i] = left_child_cv[i];
            block_words[i + 8] = right_child_cv[i];
        }
        B3Node {
            input_chaining_value: key,
            block_words,
            counter: 0,
            block_len: BLAKE3_BLOCK_LEN as u32,
            flags: flags | BLAKE3_PARENT,
        }
    }
    pub fn parent_cv<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left_child_cv: [U32Target; 8],
        right_child_cv: [U32Target; 8],
        key: [U32Target; 8],
        flags: u32,
    ) -> [U32Target; 8] {
        Self::parent_node(builder, left_child_cv, right_child_cv, key, flags)
            .chaining_value(builder)
    }
    pub fn digest<F: RichField + Extendable<D>, const D: usize, const OUTPUTS_LEN: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> [U32Target; OUTPUTS_LEN] {
        let mut node = self.chunk_state.create_node();
        let mut parent_nodes_remaining = self.cv_stack_len;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            let cv = self.cv_stack[parent_nodes_remaining];
            let right_child_cv = node.chaining_value(builder);
            node = Self::parent_node(builder, cv, right_child_cv, self.key, self.flags);
        }
        node.root_output_bytes::<F, D, OUTPUTS_LEN>(builder)
    }

    pub fn initialize<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: &[U32Target],
        flags: u32,
    ) {
        self.chunk_state = ChunkState {
            block: [builder.zero_u32(); 16],
            block_len: 0,
            blocks_compressed: 0,
            chaining_value: [
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            ],
            chunk_counter: 0,
            flags,
        };
        self.flags = flags;
    }
    pub fn push_stack(&mut self, cv: [U32Target; 8]) {
        self.cv_stack.push(cv);
        self.cv_stack_len += 1;
    }
    pub fn pop_stack(&mut self) -> [U32Target; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack.pop().unwrap()
    }
    pub fn add_chunk_chaining_value<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        new_cv: [U32Target; 8],
        total_chunks: u64,
    ) {
        let mut total_chunks = total_chunks;
        let mut t_new_cv = new_cv;
        while total_chunks & 1 == 0 {
            let cv = self.pop_stack();
            t_new_cv = Self::parent_cv(builder, cv, t_new_cv, self.key, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(t_new_cv);
    }
}


pub struct Blake3Hasher;
impl GenericCircuitMerkleHasher<Hash256Target> for Blake3Hasher{
    fn gc_two_to_one<F: RicherField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        builder.two_to_one_blake3(left, right)
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
        
      builder.hash_blake3_u32(&preimage)
    }
}


#[cfg(test)]
mod tests {
    use super::CircuitBuilderHashBlake3;
    use crate::common::base_types::hash::hash256::Hash256;
    use crate::common::binaryhelpers::bytes::bytes_to_u32_vec_le;
    use crate::common::builder::hash::hash256::{CircuitBuilderHash, WitnessHash256};
    use crate::common::u32::arithmetic_u32::CircuitBuilderU32;
    use crate::common::u32::witness::WitnessU32;
    use crate::debug::debug_timer::DebugTimer;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_blake3_two_to_one() {
        let tests = [
            [
                "A2888DCFCC56E5132D9D8C77C3F7843D7A25B1B84B8D184CBE566B8C675C79DE",
                "7A8A80B1E1AB73C015A5C1D193C59DEF7D57D4EE06AE45C0E6AD43F5885F964A",
                "352DB9F3A18F64E7A243D76150DD85CA90DDC1D10A70C574E25000C8EA25A169",
            ],
            [
                "E1A57960D2CABCD402B47F545D38CE330BBB5BED4029FD609A74BE5173661737",
                "A1044D1218EB1037704EACFF75434B0A23EED30F4404FDDBAF5FC0E160E8F7F2",
                "06F9323D023800D6066A18298A21EDB1D238DA232988D00E272C6359ACB08416",
            ],
            [
                "3F7DB25B1BC45BC4243F612A211A90D1E47AA591B5C5C0988FAFAA2137A9612D",
                "BFEDBC9152EFECE546B68CDF31C4F3B043CC499DEC9441FC060E7554D367C243",
                "83961DF656928AB1A5B6531DF4B7DDE8D02E58CA9A38019427F191B8CD17D6AA",
            ],
            [
                "BAFF37D7AA4C9B8C70963539D6B4FCA5A27671C9A2A7D093EC4E716EB233A641",
                "815439E7485F56478A2781DB8539D3F25A301F533915E8631D08D502C2516A24",
                "E41DD78ED6DF0CAA4AFFE2EE1A18C0BB90EF7F0784A60C1F2AF32F978442803E",
            ],
            [
                "B018B541A6EBAC6C5E1A6C9E9719C9BCD0C26A987192E49BDAE0130E5E6EBF7B",
                "0CF3737B820FA57F5D05593188D5AE1F66CC13973457B3EDEA28B425908504C4",
                "7189F85114FC1A252513F22F2F9AD3BB50FE50F0E7E962FD9864662BA28C117C",
            ],
            [
                "21425323F07D6CE399EBFE8EC3D97BF04AAEF9EB91707E69B91DDA6BD730084B",
                "C3E2D4D1626E2B6D5D5B51B0DDBD2BE4AF708D8ACEF5DC4126A20F45607D7C8D",
                "C87ED74002354DCADBB82386392922813C7B3500F226C172942ED9D6AF5A174E",
            ],
            [
                "91DD776904B52F3F876693288E9414705CD9DCD9EBE1899D33469514D44D1EB7",
                "AA684565BF71614203295F4DE7B4C4C042954927CFA4E6F567D7BFED9D825E15",
                "D10A4D4F5DB6A642A1BF9CC18B7D118AD4442E87F3F321F22105AC3B937917DF",
            ],
            [
                "4D14D3543701B117F142851C76DD96CDCE32DE0C5E96B03B5404A10FB0C2493C",
                "470C96FB6A3F2603DB86F92D57DFBBCDD0A5F5654EB574D5863B1E6B6F16733E",
                "079D0654B6BB7297928131DD771FCE79448A84B552EF4BE8791ADA02B6DCE8AD",
            ],
            [
                "2947EB6F9311A37688B4EDB1E9B1A546CA834B7E903CA966DDFAD043C0001B53",
                "40089B1673979E3203EFA20B017627B51F93A6AA0DD337627B90764B41D2C604",
                "93FBC8243E71236841342983AD23E4697D643D1744FD37F11467D9204C5A18FF",
            ],
            [
                "796FE704E5CCDE075DF2176EB6E426465D4CB08C0E3C0FAEF1D5484836201E20",
                "58928CE429B262D400955C03DCC03D71EE2BFAFF809F1DCE814D3E509BA5C609",
                "DE8B6FB4859758A8A60B7A26937F40052B9308B5C59441C7DBBAEF4F8CCF9789",
            ],
            [
                "48B0F93B8BF876E1B39FF0A09753CC17F14326FF2D525604B72EC3503BC26AB3",
                "2B631DFA25A64EBE735A745C315E599D5F1E94836363B2F29D841FD4607A0FFC",
                "88740A3A1098B5A83AB49A418696213B7E6F774FF397BB81AE442F35BB6F9D1F",
            ],
            [
                "4BCA7E0BE923C201C95C0F7DE13918C6AFC4CCAB97EB6EBDB884ED64F2190303",
                "020B678C4722F517421B5D96A48E55C1B3C2DF0A0080FBED5CF8A3871A681B4C",
                "2E8D2AFED144C6EC8DCF99640370AB4260DBF1F8D09FE4D6FA7ABE14EA5516A5",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut dbg_timer = DebugTimer::new("stdlib_blake3_256_two_to_one");

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let left_target = builder.add_virtual_hash256_target();
        let right_target = builder.add_virtual_hash256_target();
        let expected_output_target = builder.add_virtual_hash256_target();
        let output_target = builder.two_to_one_blake3(left_target, right_target);
        builder.connect_hash256(output_target, expected_output_target);

        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "two_to_one_blake3 num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );
        dbg_timer.lap("built circuit");

        for t in tests {
            let left = Hash256::from_str(t[0]).unwrap();
            let right = Hash256::from_str(t[1]).unwrap();
            let expected_output = Hash256::from_str(t[2]).unwrap();

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_hash256_target_le(&left_target, &left.0);
            pw.set_hash256_target_le(&right_target, &right.0);
            pw.set_hash256_target_le(&expected_output_target, &expected_output.0);
            let proof = data.prove(pw).unwrap();
            dbg_timer.lap("proved 2-to-1");
            assert!(data.verify(proof).is_ok());
        }
    }

    fn run_blake3_gadget_test_case(input: &[u32], expected_output: &[u32], key: Option<&[u8]>) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let preimage_target = builder.add_virtual_u32_targets(input.len());
        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output = if key.is_some() {
            builder.hash_blake3_u32_with_key(&preimage_target, key.unwrap())
        } else {
            builder.hash_blake3_u32(&preimage_target)
        };

        builder.connect_hash256(hash_output, expected_output_target);

        let output_targets: [Target; 8] = core::array::from_fn(|i| hash_output[i].0);
        builder.register_public_inputs(&output_targets);

        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "blake3 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len() * 4,
            num_gates,
            data.common.quotient_degree_factor
        );
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, input);
        pw.set_hash256_target_u32(&expected_output_target, expected_output);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!(
            "blake3 ({} bytes) proved in {}ms",
            input.len() * 4,
            duration_ms
        );
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    fn gen_psuedo_random_u32_vectors(seed: [u8; 32], lengths: &[usize]) -> Vec<Vec<u32>> {
        let mut rng = ChaCha8Rng::from_seed(seed);
        lengths
            .iter()
            .map(|l| {
                let len = *l;
                let mut next = Vec::new();
                for _ in 0..len {
                    next.push(rng.next_u32());
                }
                next
            })
            .collect()
    }

    #[test]
    fn test_blake3_base_tests() {
        let base_tests: Vec<(&[u8], &[u8])> = vec![
            (
                &hex_literal::hex!("0100000001000000"),
                &hex_literal::hex!("88ADA2950BDC9EE2D8C8CCB2DE23FF4123479861015241301292C84C981E5DAF"),
            ),
            (
                &hex_literal::hex!("3718CEB4122437AE80D343DFB857F4D016CA3072A05797AC24AE59918EA63C68CF97BD867F78455176EEE0709A9A59EF768E0C6D8A22BCD57ADBB3FB74A0A331F66D7E55CA3786E7C2AB91951F9A1C617CA32B34D395C745E8C15A90766735116E20A45ACA7E4BD37B7F46660E345415C758712EB9493B98C62CAD9B325B1927F7248B773E18D4E4B1D40675B3EFE7528914AD4BEDDB3BADBE05568AE539A6A308D4D2C453C726B34E84E5A6DDC5EED70026BDF5828B7A556342EFC1D8187A4BC7228D0654CB57BB"),
                &hex_literal::hex!("57c6070c7d2df36d118204842e15b868906fa80e2b2080bbdc994b48f95e7241"),
            ),
            (
                &hex_literal::hex!("38ff5e2663f834a6ad7a860f7367d404eb8a07d89f285a226b71e31d748f5bc976846ea417586b04e8ed0f00f67aa2b60cb134400190695b181a2adb20604e2d87519d5fc35f26710740bb7c6c80cc2b40bbbd3f818b09e798e8ecbc7414f2c2b44a2bdb60e630a0eddcc4323b4027be3e4aebc7edcaac6f6fb4311220b54522bce57d9ed06cdb27e4b55fc9766321c40053b0b79824b34399f479aaa47128eeaea3901416fcfa459df327c65c24333c48b7b3b28931d89afdabacb2add265ad4f4f351503ff055b4e10abc913380a1ef6942ab9fd75bd3462e296d6d8b929176f80fea37767a0ef726a6b0c7108e12e0ef0be24678f5cb5d01d2a9eb756cf033456f8cd4e26ecd86ce30f3da9c3ed9ded9b2cc155785d6541dfa7ed4a56d6eb122f4b4e7b9685f3d535ca5657e44ccec2e473bf0a2cd17a88733e2dffc6dc8ade388290c4a00ddfc075b60fb4f6fc85bfb15b8f581694728021676d696adea76f4e0618b52b03ee493e1615822af9cf1fbe97473f834d2e83428a0da63d33e7ff3a9c698883024406023143544f62da5e7d8d5b7d3b406994aa43dc1b9729fa1c9369733f2b94b2bbb12d42560e08662fd0fe8343a79446d33bae8adcc94e0c6f52ee72e0876d5b83956a306c02a57db5925eca7748cf76311b99d6e4e742c46a9036f756355811fd5a458bf6eecf91978d9739f8cb8b2f81c01e3e9b3b88e490cdccb1dccd458241139d94193daa402842d3cf0d5baaacbce1e32a01350a8a83a5cf2e35e73778825f78c18a5e94b36049a51a6c7d1287bffb0eddf83b9850d2e9653b1b43b0c4958eefe06c672b99de8a71ebe00e5f12a34912d92c5658e0923560b73b9de94fd4bdc269b638bb69622d7327a37d65593e800144d767ed434f5f307c70d2bb4852452dcd6bddbb2cd759960185d7c521314cbe688bb4f7b64e76d840290ca331bebce0b3cce22e0043e015022dc5eb74a57cf7eb0dc60f395f521b894c71b5a59354662053fa95ba867c0dba2efd67c7347be1f407e81b240887823d4e57fcf8e3722717597974bd986f1a5526138fba0c5402ba06f2f8ccd16e0db6f345049956f230c69e7afa6125d218035705eb70d372e3be83c470c2044e0719a96f5a3f6a76f72f7c94f8c5efb00b6390ffe1548f7fab75939b627b6b1e5ae1e0f5ccd3a4bfb1f6df2d96e8057a7d729551b2ec4b7237b3ffc2150a8501eb12e2f1a5843769026775ef2a39d86cdb877e2c10da7a1eab0bb1f2f4c7437fb192c0d417266b0fc9e28a1b347405556f6df7785ae33c86b357cb380c7665e1ea6a96d92f6d0285928c62eee169e04e47ebff6f2f0251547ea5d82e47187ad64a53404a51904e3b0b232d2c25fc054c9de49adb5de11a1987aa433d4c64d8cf20cf8903e9e9"),
                &hex_literal::hex!("ea04f5432ae3003eaf2696c47383adf5f658fedec1e0fa59a1a86d2cf5f598de"),
            ),
            (
                &hex_literal::hex!("95bb0468d17f33baa3ca52099681aa5523d9e86714a581113685e5f35208a59cbadcbd8dfad4ff744ccc8bf925e6b3d6f20403cdd198dc00208f9cda209e8a3d9857e32c977f063c2873166dd659b1d3a1fd7e75c83d7858b5fd5e81ba114dcd8cb97a9e7ce276182e7023fb6b317b2f0fab79b555338f8bc888ca9828c869998005b9fd25a063697630036369f3885278673c85406c3f289d468ae61e526fa44c3e8158008689884cba14bef387f0f761045081980896cb596b4c301a1ce215918ac86519433920925498599d81d110fe1225f4aae53dd704fa77a0aba0c3ae37f7b5dd798e1fc535c0431adf12622c59fb3277e7e43eaed7a42a10163779c4e15bfe1aae8284840637ada5b14250d6adefb5ac5acb088c1651f14eb01ab687d44ed3302238d22902e4eb5dec1483f8ba9f566f9e5501bc6ca27bad73a4dd288c47fa0b8ceb98a8d8ca0174d34d02ee76ecb7a6e7eb7c9e3d7457f1ef25b01e18bea7ba71b1784a0a872817c59622f93e10bb5a4eb9b600764687d234356cbdf02360220e09d361b1b65c9b4ff6761e00c65b2030966a9c86a73d647ae76b03fa46a4903e0a8173f82213e23d6d7fbeb72a07e8a92dd5949f76d72bce583452fbb2fb26ed76579a265211db98a207dd5366cee8c7d3376985e8bc2e0424f3ac0cba446509252f90d66ca36abb802d0ad27514ab8ba96b0b01b1a17793e475d4118700a1d1044899b36297905362e77c4e059382bb8154183694a95748b92a99d549eb71149bcf7b63d8e0a54d25c4dee3abd49cf21d5f7624e94337a4d25cbb7e94917ab8a20885e1d0505cf9c9b686539089c49f9192403bb56f17aee7eb3b37ff06c00511468f4339d6fb5cc70c2021705f295d2c18fc3d69eb46e9e1644f573597c8f82a047d9647e179686a8232b8f7d580d5add2b0e558c7734129d34759db1cb544a76d0df112b16a16e45aed5ee3e18ded94b3b99c5a3fd6566411f11f49d5fbab05836f2510a50febd6cfd8b3f08dae1f8f9e2d1cac9b1e64473c94804452d20d4d4f8c859d21e9c734da9bd1e4500d697891df62f08039129982c28624488c0ca134753097d48529e2830fd35ce6e915471d479420b3ab0b02386a122cc1f3d2514845110cc084dc8eaf0409b29a9e05ec5f1d19bbbc5a69488fa6313b6c12b372a5785b7df78b726f7c8eeab913e2b9474b6ac67746e49bca41652bc240c4932d476f703dcebff1b78e0e83875be883cffa4752be584a05cbfe6d838ec095b0197927706061855303a99c89503364bd0f15577d6fc149c5d93c8b5ac2717480a1c41a4cf55dafbf5b34f7cb5ab4fafb94e2452d6cc74fd6f0033d56034f81c243af744f8efcffd6b2bc992de6bd2a6b849207419f5a392d9de28419f6541d539fe51f7e17c25b464a1ccfec09e1013dae513e119cd041fd1a2028e9c1ecc8"),
                &hex_literal::hex!("9e549a64d6bc1afba6a6d7da204b42338a8d601ef5e2f87b60fbfea854a46692"),
            ),
        ];

        for t in base_tests {
            run_blake3_gadget_test_case(&bytes_to_u32_vec_le(t.0), &bytes_to_u32_vec_le(t.1), None);
        }
    }

    #[test]
    fn test_blake3_keyed() {
        let base_tests: Vec<(&[u8], &[u8], &[u8])> = vec![
            (
                &hex_literal::hex!("88f48205a48f491c8efe8c5b354477c2cff9157013769aae1774bc53124bb5edd6222ea107f639eb299b9148afc3a8d790d40c0166a9fc0af6ff672319844b3b30f4fd74a7fd545a9e2a689a5dbbf559d25731359840a09c8a9d4cc8792abe4ea95308380e0d27e5613e2209104562cfa0350b82e774357dc14ef0f07bb0f067df496c1b6396b5fdd7259aab3fa607d85b80713c788de815bdffce353794162b871aaeddbacf8e7dd7f8856c2afd3c0f83b828e42c4a3467405d57dd5d70d2bb8cd520c41e6c1326ef61c382e695f4f8ba85ae28a96d3d411822513ae99807eb31be1f3c3938ee52d280100f93cf29f16079cc88c1dcaee65861ec1d0b14492e6ab80d3d24cb090af303f94dbca8f70d3b265b798b1fe4d57957b46eaf01d46a69faa192e7ca53a2409598d1"),
                b"QED for the win",
                &hex_literal::hex!("ea22987cc77639f081b969eb1735ebf660de458dbd368d21736a66f375fd90b4"),
            ),
        ];

        for t in base_tests {
            run_blake3_gadget_test_case(
                &bytes_to_u32_vec_le(t.0),
                &bytes_to_u32_vec_le(t.2),
                Some(t.1),
            );
        }
    }

    #[test]
    fn test_blake3_pseudo_random() {
        let seed = b"test_blake3_pseudo_random_123456";
        let lengths = [
            5, 10, 15, 32, 64, 103, 128, 177, 256, 512, 729, 1024, 2048, 10000,
        ];
        let expected_outputs = [
            hex_literal::hex!("030223fde74f06258ef74e364defe2c9d8ce2be1bff9d1ba0f12a126416eed2e"),
            hex_literal::hex!("c5d4adbc67277022a0b1d1b1538a220962ad93827668e70379113f10412a325c"),
            hex_literal::hex!("2824bcb0ca4ceb8d0713826bda0952678edad1d235e3ed9e4e69b08e453709f0"),
            hex_literal::hex!("bda5ead7dff72be1fbfb8e550e641f5a5ee8bda7d74d2f86a702f6ca1b7d14b2"),
            hex_literal::hex!("c69d899128cf96b46b082b1164f60fc3644f161f851bfba44dde16d73a0af0b6"),
            hex_literal::hex!("afbfdcd173bed9567af5b30553f12bc6d72f6a48637ea70b8a006cc6303c4e42"),
            hex_literal::hex!("852f5116f15f5f3713e002d6d94cbf6bb564f65d2f25c3e71c8396ca2bf9ca98"),
            hex_literal::hex!("882d87ca66625debad2a4ad26ad369a545179902a1478568045ac0cf4689197b"),
            hex_literal::hex!("06bdfa702ac4ed6b27458b3fba681a263a2b1867a7646c5eb8326d85a0e59eca"),
            hex_literal::hex!("d5d53c51893e159a1e3871438ba13156e5714c21b6fa143db15235621cf1ffb5"),
            hex_literal::hex!("029c60b439cd07b9c9221b0c1c3f86fc4f8ee98c60168604b4ce509ff8a214e9"),
            hex_literal::hex!("f60ecd545016fe5782a7fcd8cdfccbadd432ac843d7deec686dbae979777cf3e"),
            hex_literal::hex!("59e66815101c7763636958c81bee14739ae4f934883fb7e5d5ecd7607ab0216c"),
            hex_literal::hex!("0a49576b411fa21ae27e782f08958b086b175441440562c58bb2cc9831cb4718"),
        ];

        let inputs = gen_psuedo_random_u32_vectors(*seed, &lengths);
        /*
        inputs.iter().for_each(|input|{
            println!("[\"{}\",{:?}],", hex::encode(&input.iter().flat_map(|val| val.to_le_bytes()).collect_vec()),input);
        });
        */
        for i in 0..lengths.len() {
            run_blake3_gadget_test_case(
                &inputs[i],
                &bytes_to_u32_vec_le(&expected_outputs[i]),
                None,
            );
        }
    }
}
