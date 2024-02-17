use criterion::{black_box, criterion_group, criterion_main, Criterion};
use plonky2_tree_hacks::{utils::zmt::{zero_merkle_tree::ZeroMerkleTree, node_store::{core::ZMTNodeStore, simple_node_store::SimpleNodeStore}}, common::{hash::{traits::hasher::WHasher, merkle::{helpers::merkle_proof::DeltaMerkleProof, gadgets::delta_merkle_proof::DeltaMerkleProofGadget}}, WHashOut}};
use plonky2::{field::{goldilocks_field::GoldilocksField, extension::Extendable}, hash::{hash_types::RichField, poseidon::PoseidonHash}, plonk::{circuit_data::{CircuitData, CircuitConfig}, config::{GenericConfig, AlgebraicHasher, PoseidonGoldilocksConfig}, circuit_builder::CircuitBuilder, proof::ProofWithPublicInputs}, iop::witness::PartialWitness};
use rand::random;

fn gen_random_delta_merkle_proofs<F: RichField, H: WHasher<F>, S: ZMTNodeStore<F>>(tree: &mut ZeroMerkleTree<F, H, S>, count: usize) -> anyhow::Result<Vec<DeltaMerkleProof<F>>>{
    let mut proofs: Vec<DeltaMerkleProof<F>> = vec![];
    let max_leaves = tree.max_leaves();
    for _ in 0..count {
        let index = random::<u64>() % max_leaves;
        let value = WHashOut::<F>::rand();
        let proof = tree.set_leaf(index, value)?;
        proofs.push(proof);
    }
    Ok(proofs)
}

struct DeltaMerkleProofTestCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub data: CircuitData<F, C, D>,
    pub verify_gadgets: Vec<DeltaMerkleProofGadget>,
}
impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> DeltaMerkleProofTestCircuit<F,C,D> {
    pub fn new<H: AlgebraicHasher<F>>(height: u8, num_proofs: usize)->Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let verify_gadgets: Vec<DeltaMerkleProofGadget> = (0..num_proofs).map(|_| {
            DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(
                &mut builder,
                height as usize
            )
        }).collect();
        for i in 1..num_proofs {
            builder.connect_hashes(verify_gadgets[i-1].new_root, verify_gadgets[i].old_root);
        }
        builder.register_public_inputs(&verify_gadgets[0].old_root.elements);
        builder.register_public_inputs(&verify_gadgets[verify_gadgets.len()-1].new_root.elements);
        let data = builder.build::<C>();

        Self {
            data,
            verify_gadgets,
        }
    }
    pub fn prove(&self, proofs: &Vec<DeltaMerkleProof<F>>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let num_verify_gadgets = self.verify_gadgets.len();
        assert_eq!(proofs.len(), num_verify_gadgets);
        let mut pw = PartialWitness::<F>::new();
        for i in 0..num_verify_gadgets {
            self.verify_gadgets[i].set_witness_proof(&mut pw,&proofs[i])
        }
        self.data.prove(pw)
    }
    pub fn prove_and_verify(&self, proofs: &Vec<DeltaMerkleProof<F>>) -> anyhow::Result<()>{
        let proof = self.prove(proofs)?;
        self.data.verify(proof)?;
        Ok(())
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    type F = GoldilocksField;
    type H = PoseidonHash;
    type S = SimpleNodeStore;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let num_proofs_per_circuit = 8;
    let tree_height = 32;

    let mut zmt = ZeroMerkleTree::<F, H, S>::new(tree_height, S::new());
    let proofs = gen_random_delta_merkle_proofs(&mut zmt, num_proofs_per_circuit).unwrap();
    
    let circuit = DeltaMerkleProofTestCircuit::<F, C, D>::new::<H>(tree_height, num_proofs_per_circuit);
    c.bench_function("prove", |b| b.iter(|| circuit.prove(black_box(&proofs))));
    c.bench_function("prove and verify", |b| b.iter(|| circuit.prove_and_verify(black_box(&proofs))));



    //c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
}
 



criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
