// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::io::Write;
use std::time::Instant;
use structopt::StructOpt;
//use winterfell::StarkProof;
#[cfg(feature = "std")]
use examples::sigrescue;
use examples::{fibonacci, rescue, ExampleOptions, ExampleType};

// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    // read command-line args
    let options = ExampleOptions::from_args();

    debug!("============================================================");

    // instantiate and prepare the example
    let example = match options.example {
        ExampleType::Fib { sequence_length } => {
            fibonacci::fib2::get_example(&options, sequence_length)
        }
        ExampleType::Mulfib8 { sequence_length } => {
            fibonacci::mulfib8::get_example(&options, sequence_length)
        }
        ExampleType::Rescue { chain_length } => rescue::get_example(&options, chain_length),
        #[cfg(feature = "std")]
        ExampleType::SigRescue { num_signers } => sigrescue::get_example(&options, num_signers),
    }
    .expect("The example failed to initialize.");

    // generate proof
    let now = Instant::now();
    let example = example.as_ref();
    let proof = example.prove();
    debug!(
        "---------------------\nProof generated in {} ms",
        now.elapsed().as_millis()
    );

    let proof_bytes = proof.to_bytes();
    debug!("Proof size: {:.1} KB", proof_bytes.len() as f64 / 1024f64);
    let conjectured_security_level = options.get_proof_security_level(&proof, true);

    #[cfg(feature = "std")]
    {
        // let proven_security_level = options.get_proof_security_level(&proof, false);
        // debug!(
        //     "Proof security: {} bits ({} proven)",
        //     conjectured_security_level, proven_security_level,
        // );
        debug!("Proof security: {} bits", conjectured_security_level,);
    }

    #[cfg(not(feature = "std"))]
    debug!("Proof security: {} bits", conjectured_security_level);

    // #[cfg(feature = "std")]
    // debug!(
    //     "Proof hash: {}",
    //     hex::encode(blake3::hash(&proof_bytes).as_bytes())
    // );

    // verify the proof
    debug!("---------------------");
    // let parsed_proof = StarkProof::from_bytes(&proof_bytes).unwrap();
    // assert_eq!(proof, parsed_proof);
    let now = Instant::now();
    match example.verify(proof) {
        Ok(_) => debug!(
            "Proof verified in {:.1} ms",
            now.elapsed().as_micros() as f64 / 1000f64
        ),
        Err(msg) => debug!("Failed to verify proof: {}", msg),
    }
    debug!("============================================================");
}
