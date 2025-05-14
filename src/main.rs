mod circuit;
mod utils;
mod party;
mod gc;

use crate::gc::GarbledCircuit;
use crate::party::GarbleResult;
use std::collections::VecDeque;
use crate::gc::WireLabel;
use crate::gc::GarbleAnd;
use rand::Rng;

fn main(){
    // let rawData = b"abdc";
    let rawData = b"abdcabdcbdcabdcabdcabdcbdcabdcabdcabdcbdcabdcabdcabdcbdcabdcabdcabdcbdcabdcabdcababdcabdcabdcbdcabdcb";
    let message = rawData.to_vec();
    let length = message.len();

    // Create two vectors of the same length
    let mut rng = rand::thread_rng();
    let mut vec0 = vec![0u8; length];
    let mut vec1 = vec![0u8; length];
    rng.fill(&mut vec0[..]);

    // Calculate vec2 using XOR operation
    for i in 0..length {
        vec1[i] = message[i] ^ vec0[i];
    }

    let desired_result = utils::sha256(rawData);
    //----- Garbled circuit evaluation test on the sha256 circuit------------//
    let p0 =  match party::Party::new(0,&vec0){
            Ok(mut p0) => {
            let mut result:GarbleResult = p0.start_garbling( );
                let p1 =  match party::Party::new(1,&vec1){
                Ok(mut p1) => {
                         let output_bytes:Vec<u8> = p1.start_evaluating(&mut result);
                         let hex_string1: String = output_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();

                          println!("Verify: The desired   hash computation: {}", desired_result);
                          println!("Verify: Final garbled hash computation: {}", hex_string1);
                          assert_eq!(hex_string1, desired_result,"The garbled result is wrong!!");

                        },
                        Err(e) => {
                        println!("Failed to create circuit: {}", e);
                    },
                };
            },
            Err(e) => {
            println!("Failed to create circuit: {}", e);
        },
    };
}