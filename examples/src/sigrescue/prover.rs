use super::{
    rescue, AggPublicKey, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData,
    ProofOptions, Prover, PublicInputs, RingSigAir, TraceTable, HASH_CYCLE_LENGTH, SIGN_LENGTH,
    TRACE_WIDTH,
};
use rand_utils::rand_value;
#[cfg(feature = "concurrent")]
use winterfell::iterators::*;
use winterfell::Trace;

// PROVER
// ================================================================================================

pub struct RingSigProver<H: ElementHasher> {
    pub_inputs: PublicInputs,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RingSigProver<H> {
    pub fn new(
        root: &AggPublicKey,
        tag: [BaseElement; 2],
        eventid: BaseElement,
        options: ProofOptions,
    ) -> Self {
        let pub_inputs = PublicInputs {
            pub_key_root: root.root().to_elements(),
            num_pub_keys: root.num_keys(),
            tag,
            eventid,
        };
        Self {
            pub_inputs,
            options,
            _hasher: PhantomData,
        }
    }

    pub fn build_trace(
        &self,
        root: &AggPublicKey,
        signer_sk: &[BaseElement; 2],
        signer_idx: u128,
        eventid: BaseElement,
    ) -> TraceTable<BaseElement> {
        // get the authentication path of signer's index
        let key_path = root.get_leaf_path(signer_idx as usize);
        let key_path = &key_path[1..];

        // define the execution trace length
        let trace_length = SIGN_LENGTH + HASH_CYCLE_LENGTH * (key_path.len());

        // pad the trace length to a power of 2
        let padding_length = trace_length.next_power_of_two();
        let mut trace = TraceTable::new(TRACE_WIDTH, padding_length);

        // get the signer's index bit sequence
        let mut index_bit = Vec::new();
        for i in 0..key_path.len() {
            index_bit.push(BaseElement::from((signer_idx >> (i)) & 1))
        }
        index_bit.pop();

        let mut state = vec![BaseElement::ZERO; trace.main_trace_width()];
        let mut step = 0;

        // step 8
        // define the trace of tag
        state[0] = BaseElement::ZERO;
        state[1] = signer_sk[0];
        state[2] = signer_sk[0];
        state[3] = eventid;
        state[4..].fill(BaseElement::ZERO);
        trace.update_row(step, &state);
        step += 1;

        while step < HASH_CYCLE_LENGTH {
            rescue::apply_round(&mut state[2..], step - 1);
            trace.update_row(step, &state);
            step += 1;
        }

        // define the trace of hashing the signer's secret key, resulting in public keys
        state[1] = BaseElement::ZERO;
        state[2] = signer_sk[0];
        state[3] = signer_sk[1];
        state[4..].fill(BaseElement::ZERO);
        trace.update_row(step, &state);
        step += 1;

        let mut i = 0;
        while step < HASH_CYCLE_LENGTH * 2 {
            rescue::apply_round(&mut state[2..], i);
            trace.update_row(step, &state);
            step += 1;
            i += 1;
        }

        // define the trace of hashing public keys
        state[1] = BaseElement::ZERO;
        state[4..].fill(BaseElement::ZERO);
        trace.update_row(step, &state);
        step += 1;

        i = 0;
        while step < padding_length {
            let cycle_num = i / HASH_CYCLE_LENGTH;
            let cycle_pos = i % HASH_CYCLE_LENGTH;

            if cycle_pos < HASH_CYCLE_LENGTH - 1 {
                rescue::apply_round(&mut state[2..], cycle_pos);
                let rand1: u64 = rand_value();
                state[0] = BaseElement::from(rand1);
            } else {
                let branch_rand1: u64 = rand_value();
                let branch_rand2: u64 = rand_value();

                let branch_node = match key_path.get(cycle_num) {
                    Some(v) => v.to_elements(),
                    None => [
                        BaseElement::from(branch_rand1),
                        BaseElement::from(branch_rand2),
                    ], //None => Default::default(),
                };
                let index_bit = BaseElement::new((signer_idx >> cycle_num) & 1);

                if index_bit == BaseElement::ZERO {
                    // if index bit is zero, new branch node goes into registers [3, 4]; values
                    // in registers [1, 2] (the accumulated hash) remain unchanged
                    state[4] = branch_node[0];
                    state[5] = branch_node[1];
                } else {
                    // if index bit is one, accumulated hash goes into registers [3, 4],
                    // and new branch nodes goes into registers [1, 2]
                    state[4] = state[2];
                    state[5] = state[3];
                    state[2] = branch_node[0];
                    state[3] = branch_node[1];
                }
                // reset the capacity registers of the state to ZERO
                state[6..].fill(BaseElement::ZERO);

                // set the index bit
                state[0] = index_bit;

                let rand1: u64 = rand_value();
                state[1] = BaseElement::from(rand1);
            }
            trace.update_row(step, &state);
            step += 1;
            i += 1;
        }
        trace
    }
}

impl<H: ElementHasher> Prover for RingSigProver<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = RingSigAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

// fn message_to_elements(message: &[u8]) -> [BaseElement; 2] {
//     // reduce the message to a 32-byte value
//     let hash = *blake3::hash(message).as_bytes();

//     // interpret 32 bytes as two 128-bit integers
//     let mut m0 = u128::from_le_bytes(hash[..16].try_into().unwrap());
//     let mut m1 = u128::from_le_bytes(hash[16..].try_into().unwrap());

//     // clear the most significant bit of the first value to ensure that it fits into 127 bits
//     m0 = (m0 << 1) >> 1;

//     // do the same thing with the second value, but also clear 8 more bits to make room for
//     // checksum bits
//     m1 = (m1 << 9) >> 9;

//     // compute the checksum and put it into the most significant bits of the second values;
//     // specifically: bit 127 is zeroed out, and 8 bits of checksum should go into bits
//     // 119..127 thus, we just shift the checksum left by 119 bits and OR it with m1 (which
//     // has top 9 bits zeroed out)
//     let checksum = m0.count_zeros() + m1.count_zeros();
//     let m1 = m1 | ((checksum as u128) << 119);

//     [BaseElement::from(m0), BaseElement::from(m1)]
// }
