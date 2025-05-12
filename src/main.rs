
// use hex;
mod circuit;
mod utils;
mod gc;

use crate::gc::GarbledCircuit;
use crate::gc::GarbleResult;
use std::collections::VecDeque;
use crate::gc::WireLabel;
use crate::gc::GarbleAnd;

fn main(){
    // let rawData = b"abdc";
    let rawData = b"abdc";

    let message = rawData.to_vec();

    println!("message vec is : {:?}", message);

    let other_message = vec![0; message.len()];

    let input_bits_cnt:usize = message.len()*8;


    let circuit =  match circuit::Sha256Circuit::new( message.len() ){
        Ok(circuit) => {
            circuit.display();
            //-----Plaintext evaluation test on the bristol circuit------------//
            let desired_result = utils::sha256(rawData);
            let bytes:Vec<u8> = utils::planitext_eval(&message, &circuit);
            let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
            assert_eq!(hex_string, desired_result,"The evaluated result is wrong!!");

            //----- Garbled circuit evaluation test on the bristol circuit------------//
            let mut garbler = GarbledCircuit::new();
            let result:GarbleResult = garbler.garble( &message, &circuit);

            //TODO: Receive messages from network
            let mut input_wires: Vec<WireLabel> = Vec::from(result.p0_label0);
            for i in 0..input_bits_cnt{
                input_wires.push(result.p1_labels[2*i]);
            }

            let mut evaluator = GarbledCircuit::new();
            let mut and_deque: VecDeque<GarbleAnd> = VecDeque::from(result.garbled_and);//Convert Vec to VecDeque
            let ret:Vec<u8> = evaluator.evaluate(&circuit, &input_wires, &mut and_deque, &result.permu_bits);

            let hex_string1: String = ret.iter().map(|byte| format!("{:02x}", byte)).collect();
            // println
            println!("Verify: The desired   hash computation: {}", desired_result);
            println!("Verify: Final garbled hash computation: {}", hex_string1);
            assert_eq!(hex_string1, desired_result,"The garbled result is wrong!!");
        },
        Err(e) => {
            println!("Failed to create circuit: {}", e);
        },
    };
}