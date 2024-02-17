use plonky2_tree_hacks::{common::{hash::merkle::{gadgets::delta_merkle_proof::DeltaMerkleProofGadget, helpers::merkle_proof::DeltaMerkleProof}, u32::multiple_comparison::list_le_circuit, WHashOut}, utils::zmt::{node_store::simple_node_store::SimpleNodeStore, zero_merkle_tree::ZeroMerkleTree}};
use plonky2::{field::{extension::Extendable, goldilocks_field::GoldilocksField}, hash::{hash_types::RichField, poseidon::PoseidonHash}, iop::witness::PartialWitness, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}};

pub struct BalanceUpdateGadget {
    pub sender_update: DeltaMerkleProofGadget,
    pub receiver_update: DeltaMerkleProofGadget,
}
pub struct BalanceUpdate<F: RichField> {
    pub sender_update: DeltaMerkleProof<F>,
    pub receiver_update: DeltaMerkleProof<F>,
}
impl BalanceUpdateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        tree_height: usize,
    ) -> Self {
        let sender_update = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(
            builder,
            tree_height,
        );
        let receiver_update = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(
             builder,
            tree_height,
        );

        let amount_recv = builder.sub(receiver_update.new_value.elements[0], receiver_update.old_value.elements[0]);
        let amount_send = builder.sub(sender_update.old_value.elements[0], sender_update.new_value.elements[0]);
        builder.connect(amount_recv, amount_send);




        let overflow_checks = list_le_circuit(builder, vec![receiver_update.old_value.elements[0], sender_update.new_value.elements[0]], vec![receiver_update.new_value.elements[0], sender_update.old_value.elements[0]], 32);
        let true_target = builder.one();
        builder.connect(overflow_checks.target,true_target);


        builder.connect_hashes(sender_update.new_root, receiver_update.old_root);
        Self {
            sender_update,
            receiver_update,
        }
    }
    pub fn set_witness_proof<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        input: &BalanceUpdate<F>,
    ) {
        self.sender_update.set_witness_proof(witness, &input.sender_update);
        self.receiver_update.set_witness_proof(witness, &input.receiver_update);
    }
}


pub struct UpdateBalanceCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub updates: Vec<BalanceUpdateGadget>,
    pub base_circuit_data: CircuitData<F, C, D>,
}


impl<
F: RichField + Extendable<D>,
C: GenericConfig<D, F = F> + 'static,
const D: usize,
> UpdateBalanceCircuit<F,C,D> where
<C as GenericConfig<D>>::Hasher: AlgebraicHasher<F> {
    pub fn new(number_updates: usize, tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let updates: Vec<BalanceUpdateGadget> = (0..number_updates).map(|_| {
            BalanceUpdateGadget::add_virtual_to::<C::Hasher, F, D>(
                &mut builder,
                tree_height
            )
        }).collect();
        for i in 1..number_updates {
            builder.connect_hashes(updates[i-1].receiver_update.new_root, updates[i].sender_update.old_root);
        }
        builder.register_public_inputs(&updates[0].sender_update.old_root.elements);
        builder.register_public_inputs(&updates[updates.len()-1].receiver_update.new_root.elements);
        let base_circuit_data = builder.build::<C>();
        Self {
            updates,
            base_circuit_data,
        }
    }
    pub fn prove(&self, proofs: &Vec<BalanceUpdate<F>>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let num_updates = self.updates.len();
        assert_eq!(proofs.len(), num_updates);
        let mut pw = PartialWitness::<F>::new();
        for i in 0..num_updates {
            self.updates[i].set_witness_proof(&mut pw,&proofs[i])
        }
        self.base_circuit_data.prove(pw)
    }


}
pub struct BalanceStorage {
    pub tree: ZeroMerkleTree<GoldilocksField, PoseidonHash, SimpleNodeStore>,
}

impl BalanceStorage {
    pub fn new(height: u8, start_balances: Vec<u32>) -> Self {
        let mut tree = ZeroMerkleTree::<GoldilocksField, PoseidonHash, SimpleNodeStore>::new(height, SimpleNodeStore::new());

        for (i, balance) in start_balances.iter().enumerate() {
            tree.set_leaf(i as u64, WHashOut::from_values((*balance) as u64, 0,0, 0)).unwrap();
        }
        Self {
            tree,
        }
    }
    pub fn get_balance(&self, index: u64) -> anyhow::Result<u32> {
        let balance_proof = self.tree.get_leaf(index)?;
        
        
        Ok(balance_proof.value.0.elements[0].0 as u32)
    }
    pub fn set_balance(&mut self, index: u64, value: u32) -> anyhow::Result<DeltaMerkleProof<GoldilocksField>> {
        let leaf_value = WHashOut::from_values(value as u64, 0,0,0);
        
        self.tree.set_leaf(index, leaf_value)
    }
    pub fn process_tx(&mut self, sender: u64, receiver: u64, amount: u32) -> anyhow::Result<BalanceUpdate<GoldilocksField>> {
        let sender_balance = self.get_balance(sender)?;
        let receiver_balance = self.get_balance(receiver)?;
        println!("Sender balance: {}", sender_balance);
        assert!(sender_balance >= amount, "Insufficient funds");

        let sender_proof: DeltaMerkleProof<GoldilocksField> = self.set_balance(sender, sender_balance-amount)?;
        let receiver_proof = self.set_balance(receiver, receiver_balance+amount)?;
        Ok(BalanceUpdate { sender_update: sender_proof, receiver_update: receiver_proof })
    }
    pub fn process_txs(&mut self, txs: Vec<(u64, u64, u32)>) -> anyhow::Result<Vec<BalanceUpdate<GoldilocksField>>> {
        let mut proofs = vec![];
        for (sender, receiver, amount) in txs {
            proofs.push(self.process_tx(sender, receiver, amount)?);
        }
        Ok(proofs)
    }

}
fn main() {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
        
    let example_circuit = UpdateBalanceCircuit::<F, C, D>::new(2, 32);
    let mut storage = BalanceStorage::new(32, vec![100, 100, 100, 100]);
    //println!("{:?}", storage.tree.get_leaf(0).unwrap());

    let balance_updates = storage.process_txs(vec![(0, 1, 10), (2, 3, 20)]).unwrap();

    let proof = example_circuit.prove(&balance_updates).unwrap();
    example_circuit.base_circuit_data.verify(proof).unwrap();
    println!("verified!")




}