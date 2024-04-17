use super::Example;
use crate::utils::rescue::{self, Rescue128, CYCLE_LENGTH as HASH_CYCLE_LENGTH};
use crate::{Blake3_192, Blake3_256, ExampleOptions, HashFunction, Sha3_256};
use core::marker::PhantomData;
use log::debug;
use rand_utils::{prng_vector, rand_value};
use std::time::Instant;
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher},
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, Prover, StarkProof, Trace, TraceTable, VerifierError,
};
mod signature;
use signature::AggPublicKey;

mod air;
use air::{PublicInputs, RingSigAir};

mod prover;
use prover::RingSigProver;

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 8;
const SIGN_LENGTH: usize = 24;
const NUM_QUERIES: usize = 28;
const BLOWUP_FACTOR: usize = 8;
const SIGNER_IDX: u128 = 1;
const EVENTID: u8 = 2;

pub fn get_example(
    options: &ExampleOptions,
    num_signers: usize,
) -> Result<Box<dyn Example>, String> {
    let (_, hash_fn) = options.to_proof_options(NUM_QUERIES, BLOWUP_FACTOR);

    match hash_fn {
        HashFunction::Blake3_192 => Ok(Box::new(RingSigExample::<Blake3_192>::new(
            num_signers,
            options,
        ))),
        HashFunction::Blake3_256 => Ok(Box::new(RingSigExample::<Blake3_256>::new(
            num_signers,
            options,
        ))),
        HashFunction::Sha3_256 => Ok(Box::new(RingSigExample::<Sha3_256>::new(
            num_signers,
            options,
        ))),
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct RingSigExample<H: ElementHasher> {
    options: ProofOptions,
    root: AggPublicKey,
    signer_sk_key: [BaseElement; 2],
    pks: Vec<[BaseElement; 2]>,
    signer_idx: u128,
    tag: [BaseElement; 2],
    eventid: BaseElement,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RingSigExample<H> {
    pub fn new(num_signers: usize, options: &ExampleOptions) -> Self {
        //num signer excludes real signer

        let num_signers = (num_signers + 1).next_power_of_two() - 1;
        // message to be signed
        // let message = "test message";

        let now = Instant::now();

        let sk_sequence = prng_vector::<BaseElement>([rand_value(); 32], num_signers + 1);
        let mut sk_vec = Vec::new();
        for c in 0..=num_signers {
            sk_vec.push([sk_sequence[c], BaseElement::ONE]);
        }
        let pk_vec = sk_vec
            .iter()
            .map(|sk| Rescue128::digest(sk).to_elements())
            .collect::<Vec<_>>();

        let signer_sk = sk_vec[SIGNER_IDX as usize];
        debug!(
            "Generate public keys and secret keys in {} ms",
            now.elapsed().as_millis()
        );
        let bytes1 = BaseElement::elements_as_bytes(&pk_vec[0]);
        debug!("Public key size: {:.1} bytes", bytes1.len());

        let tag_input = [signer_sk[0], BaseElement::from(EVENTID)];
        let tag = Rescue128::digest(&tag_input).to_elements();

        let eventid = BaseElement::from(EVENTID);

        let now = Instant::now();
        let root = AggPublicKey::new(pk_vec.clone());

        debug!(
            "Built merkle tree for public keys in {} ms",
            now.elapsed().as_millis()
        );

        let (options, _) = options.to_proof_options(NUM_QUERIES, BLOWUP_FACTOR);

        RingSigExample {
            options,
            root,
            signer_sk_key: signer_sk,
            // message: message_to_elements(message.as_bytes()),
            pks: pk_vec,
            signer_idx: SIGNER_IDX,
            tag,
            eventid,
            _hasher: PhantomData,
        }
    }
}

impl<H: ElementHasher> Example for RingSigExample<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for verifying ring signature with {} members \n\
            ---------------------",
            self.pks.len(),
        );

        // create a prover
        let prover =
            RingSigProver::<H>::new(&self.root, self.tag, self.eventid, self.options.clone());

        // generate execution trace
        let now = Instant::now();
        let trace = prover.build_trace(
            &self.root,
            &self.signer_sk_key,
            self.signer_idx,
            self.eventid,
        );

        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and {} steps in {} ms",
            trace.width(),
            trace_length,
            now.elapsed().as_millis()
        );

        debug!(
            "Generated the tag for linkable ring signature",
            // self.tag,
        );

        // trace.get_column(1).chunks(8).for_each(|row| println!("{:?}", row));
        // println!("values");
        //println!("values: {}",trace.get(1,7));

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        //let msg = message_to_elements("test message".as_bytes());
        let pub_inputs = PublicInputs {
            pub_key_root: self.root.root().to_elements(),
            num_pub_keys: self.pks.len(),
            tag: self.tag,
            eventid: self.eventid,
        };
        winterfell::verify::<RingSigAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            pub_key_root: self.root.root().to_elements(),
            num_pub_keys: self.pks.len() + 1,
            tag: self.tag,
            eventid: self.eventid,
        };
        winterfell::verify::<RingSigAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
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
