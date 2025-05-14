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
use std::env;

fn main(){
    // Collect command-line arguments into a vector
    let args: Vec<String> = env::args().collect();

    // Check if the user provided an argument
    if args.len() < 2 {
        eprintln!("Please input a positive integer!");
        return;
    }

    // Parse the argument as a positive integer
    let n: usize = match args[1].parse() {
        Ok(num) if num > 0 => num, // Check if the number is positive
        _ => {
            eprintln!("Please provide a valid positive integer!");
            return;
        }
    };

    let mut rng = rand::thread_rng();
    let mut message:Vec<u8> = Vec::new();
    for _ in 0..n {
        let random_char = if rng.gen_bool(0.5) { // Choose between uppercase and lowercase
            rng.gen_range(b'A'..=b'Z') // Uppercase A-Z
        } else {
            rng.gen_range(b'a'..=b'z') // Lowercase a-z
        };
        message.push(random_char);
    }


    let length = message.len();
    let mut vec0 = vec![0u8; length];
    let mut vec1 = vec![0u8; length];
    rng.fill(&mut vec0[..]);

    // Calculate vec2 using XOR operation
    for i in 0..length {
        vec1[i] = message[i] ^ vec0[i];
    }

    let desired_result = utils::sha256(message.as_slice());
    //----- Garbled circuit evaluation test on the sha256 circuit------------//
    let p0 =  match party::Party::new(0,&vec0){
            Ok(mut p0) => {
            let mut result:GarbleResult = p0.start_garbling( );

            println!("\n ................................................... \n");

                let p1 =  match party::Party::new(1,&vec1){
                Ok(mut p1) => {
                         let output_bytes:Vec<u8> = p1.start_evaluating(&mut result);
                         let hex_string1: String = output_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();

                          println!("Input message: {}", String::from_utf8(message).expect("Invalid UTF-8 sequence"));
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