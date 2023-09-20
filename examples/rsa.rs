use std::{collections::HashMap, env::current_dir, time::Instant};

use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{
    provider,
    traits::{circuit::StepCircuit, Group},
    CompressedSNARK, PublicParams,
};
use serde_json::json;

fn run_test(circuit_filepath: String, witness_gen_filepath: String) {
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;

    println!(
        "Running test with witness generator: {} and group: {}",
        witness_gen_filepath,
        std::any::type_name::<G1>()
    );
    let iteration_count = 16;
    let root = current_dir().unwrap();

    let circuit_file = root.join(circuit_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file = root.join(witness_gen_filepath);

    // let modulus = [ 7393733765198893753,  15021702840859770572,
    //   7791099558876688176,  13358531286313426663,
    //   220964654821867891,   12127583786530579557,
    //   4284074925254610676,  12791660227890158665,
    //   5287463645693083792,  14146517856241052685,
    //   1551382107775512883,  5583525925678336154,
    //   630770580733901677,   11344036437445967560,
    //   5442456374462632955,  8824600348477149085,
    //   16013047011490152554, 881740173685966498,
    //   17349640094304204496, 4107271532411575765,
    //   7485350056758160279,  2177551449296720977,
    //   7677962950361984035,  2086588424853660202,
    //   14215491066227096835, 1794722798567678506,
    //   14165395421177685934, 11666076404411987464,
    //   2913723460956784920,  9122382708731008767,
    //   2332020847133510385,  14440780336709191350
    //   ];

    // let converted = <[Fq; 32] as TryFrom<Vec<Fq>>>::try_into(
    //   modulus.iter()
    //       .map(|&num| F::<G1>::from(num))
    //       .collect::<Vec<_>>()
    // );
    
    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("iiiii".to_string(), json!(i));
        private_inputs.push(private_input);
    }



    // step_in, modulus

    let start_public_input_ints = [
      3421439721559149319,  11354732770515695799,
      4227317210642278584,  14606982623262455573,
      17546405983876959373, 10259133504878202111,
      4082821270767945977,  17449369643899344788,
      7746950233964549303,  13134713490114596675,
      17916351255307472858, 2968229864166344234,
      12986871368453415689, 2127338031857367579,
      9597868595081610645,  16048860333519980468,
      12889691138810385032, 13165199160586510530,
      1534606364301995300,  1189102230710267931,
      15702306784120788195, 491332807642141714,
      15837352471120481694, 612509762454378322,
      11280499346254295604, 6529152347632750885,
      2969316828717622690,  12186249902756252792,
      8972631233870835705,  11845974461683939086,
      1978506114271498453,  4438562012349718266,
  
      7393733765198893753,  15021702840859770572,
      7791099558876688176,  13358531286313426663,
      220964654821867891,   12127583786530579557,
      4284074925254610676,  12791660227890158665,
      5287463645693083792,  14146517856241052685,
      1551382107775512883,  5583525925678336154,
      630770580733901677,   11344036437445967560,
      5442456374462632955,  8824600348477149085,
      16013047011490152554, 881740173685966498,
      17349640094304204496, 4107271532411575765,
      7485350056758160279,  2177551449296720977,
      7677962950361984035,  2086588424853660202,
      14215491066227096835, 1794722798567678506,
      14165395421177685934, 11666076404411987464,
      2913723460956784920,  9122382708731008767,
      2332020847133510385,  14440780336709191350
    ];

    // let start_public_input = [F::<G1>::from(10), F::<G1>::from(10)];
    let start_public_input: [F<G1>; 64] = start_public_input_ints
    .iter()
    .map(|&num| F::<G1>::from(num))
    .collect::<Vec<_>>()
    .try_into()
    .unwrap();

    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file),
        r1cs,
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    // TODO: empty?
    let z0_secondary = [F::<G2>::from(0)];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();

    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
}

fn main() {
    let circuit_filepath = format!("examples/rsa/rsa.r1cs");
    for witness_gen_filepath in [
        // format!("examples/rsa/{}/rsa_cpp/rsa", group_name),
        format!("examples/rsa/rsa_js/rsa.wasm"),
    ] {
        run_test(circuit_filepath.clone(), witness_gen_filepath);
    }
}
