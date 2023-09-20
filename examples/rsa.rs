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
    let iteration_count = 2; //16
    let root = current_dir().unwrap();

    let circuit_file = root.join(circuit_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file = root.join(witness_gen_filepath);

    let intermediate_result = [
      [
      "3248130727840117131",
      "8754168099710501821",
      "17166556127366315777",
      "17586917352601055794",
      "9020254741720614141",
      "2474069031187499837",
      "13622343891876279280",
      "10379245415602051328",
      "18067831147019880360",
      "1288754433873975610",
      "8286453026039635",
      "6816790802703779208",
      "14931970097532325162",
      "8727989097281690762",
      "16770278023718558383",
      "11824684004220778527",
      "12041714549741581384",
      "1375772270321465775",
      "10440937374196075651",
      "7660794131771569759",
      "10375106853077924052",
      "7540853415204145893",
      "14133043432083813021",
      "14274617160026751117",
      "5195938493564030273",
      "15135609232869746417",
      "128259737357664897",
      "2143467336863843863",
      "11503088194804732502",
      "12945618310455145775",
      "1011127539071714375",
      "3207299829674605865",
    ], [
      "5039992027621760657",
      "15189447381536583509",
      "8985634801216599720",
      "12497198905654951001",
      "8347454284382845625",
      "6493050133067442753",
      "4254709800309989283",
      "15628981479099237571",
      "17926738739118738766",
      "16742384033307422403",
      "8672450018744702006",
      "10496218142438241151",
      "10678690582799554019",
      "18122237697100921969",
      "13979905804296935944",
      "2579746104820193646",
      "941361764934440239",
      "1978202206574253913",
      "4345235140720176003",
      "16376384376819692532",
      "17818514318688254128",
      "14091579900467436303",
      "8758228538938025018",
      "10314471768811108863",
      "1710971630918550814",
      "2743907947797015758",
      "5758220408967489705",
      "12320716816246105829",
      "4104458599733921561",
      "17702272431730727324",
      "15330945659580181357",
      "4029298535526590227"]
      ];

    // let formatted_intermediate_result: [F<G1>; 32] = intermediate_result
    //   .iter()
    //   .map(|&num| F::<G1>::from(num))
    //   .collect::<Vec<_>>()
    //   .try_into()
    //   .unwrap();

    let mut private_inputs = Vec::new();

    
    for i in 0..iteration_count {
      let mut private_input = HashMap::new();
      private_input.insert("intermediate_result".to_string(), json!(intermediate_result[i]));
      private_inputs.push(private_input);
    }
    println!("Private inputs: {:?}", private_inputs);



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




