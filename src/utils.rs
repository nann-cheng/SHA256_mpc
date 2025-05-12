use std::collections::HashMap;
use sha2::{Sha256, Digest};
use crate::circuit::Sha256Circuit;
use crate::circuit::PlainEvalWire;

// Input label and output label are very well done..
pub fn sha256(message: &[u8]) -> String {
    // Create a Sha256 hasher instance
    let mut hasher = Sha256::new();
    // Write the message to the hasher
    hasher.update(message);
    // Read the hash result
    let result = hasher.finalize();
    // Return the SHA-256 hash as a hexadecimal string
    hex::encode(result)
}

// From message lengh (in bits), compute the padding bits up to a whole block (512 bits)
 pub fn get_padded_bits( bytesLen:usize ) -> Vec<bool> {
    let mut appended_bits:Vec<bool> = Vec::new();
    appended_bits.push(true);
    //Append '0' bits until the length is congruent to 448 mod 512
    while (appended_bits.len() + bytesLen * 8) % 512 != 448 {
        appended_bits.push(false);
    }
    let message_len_in_bits:u64 = (bytesLen * 8) as u64;
    // Step 3: Append the length of the original message as a 64-bit integer
    for i in (0..64).rev() {
        appended_bits.push((message_len_in_bits >> i) & 1  == 1); // Push true if bit is 1, false if 0
    }
    appended_bits
}

pub fn convertBytes2Bits(message:&Vec<u8>) -> Vec<bool>{
    let mut bits = vec![false; message.len()*8];
    // Convert padded_message to bits
    for (byte_index, &byte) in message.iter().enumerate() {
        for bit_index in 0..8 {
            let overall_index = byte_index * 8 + bit_index;
            bits[overall_index] = ((byte >> (7 - bit_index)) & 1) == 1; //Extract the bit and convert to bool
        }
    }
    bits
}

//assume len(bits) is a multiple of 8
pub fn convertBits2Bytes(bits:&Vec<bool>) -> Vec<u8>{
    assert!(bits.len()%8==0,"The bits length must be a mulitple of 8!");
    let mut output_bytes: Vec<u8> = Vec::new();
    for i in 0..bits.len()/8 {
        let mut byte: u8 = 0; // Initialize the byte
        for j in 0..8 {
            if bits[i * 8 + j] {
                byte |= 1 << (7 - j); // Set the bit position (7 - j) to 1
            }
        }
        output_bytes.push(byte);
    }
    output_bytes
}

pub fn planitext_eval(message:&Vec<u8>, circuit:&Sha256Circuit) -> Vec<u8> {
    // It stores every k-v: wire_number - evaluation results
    // let mut evaluation_map: HashMap<usize, bool> = HashMap::new();
    let mut evaluation_map: HashMap<usize, PlainEvalWire> = HashMap::new();

    //-----Step-0: Prepare plaintext values for all input wires from two parties------------//
    let bits = convertBytes2Bits(message);

    //-----Step-1: Set values for input wires from two parties------------//
    //for XOR gate part input wires
    for (i,wire_id) in circuit.input_wires_0.iter().enumerate(){//fill in bits from party 0
        evaluation_map.insert(*wire_id, PlainEvalWire{val:bits[i], flipped: false} );
    }
    for i in &circuit.input_wires_1{
        evaluation_map.insert( *i, PlainEvalWire{val:false, flipped: false});
    }
    for public_wire in &circuit.public_input_wires{
        evaluation_map.insert( public_wire.id, PlainEvalWire{val:public_wire.bit, flipped: false} );
    }

    //----------Step-2: Evaluate the circuit gate by gate------------//
    for gate in &circuit.gates {
        // let mut input0:bool = false;
        // let mut input1:bool = false;
        match evaluation_map.get(&gate.input0) {
            Some(value) => {//this evaluation value might also be flipped
                match evaluation_map.get(&gate.input1) {
                    Some(value1) => {//this evaluation value might also be flipped
                        let mut out:bool=false;
                        let mut out_flipped:bool=false;
                        if gate.gateType{//AND gate
                            let mut real_input0:bool = value.val ^ value.flipped ^ gate.input0_flipped;
                            let mut real_input1:bool = value1.val ^ value1.flipped ^ gate.input1_flipped;
                            out = real_input0 && real_input1;
                        }else{//XOR gate
                            out = value.val ^ value1.val;
                            out_flipped = (value.flipped ^ gate.input0_flipped) ^ (value1.flipped ^ gate.input1_flipped);
                        }
                        evaluation_map.insert(gate.output, PlainEvalWire{val:out, flipped: out_flipped});
                    },
                    None => {
                        println!("Key {} not found when fetch input1", gate.input1);
                    },
                }
            },
            None => {
                println!("Key {} not found when fetch input0", gate.input0);
            },
        }
    }

    //Step-3: fetch the final output wires
    let mut output_bits: Vec<bool> = Vec::new();; // Creates a Vec<bool> with 256 false values
    for (i, output_wire) in circuit.output_wire_ids.iter().enumerate() {
        let mut real_id:usize = output_wire.id;
        if output_wire.should_trace{//A not gate is applied here
            real_id = output_wire.input_id;
        }
        match evaluation_map.get( &real_id ) {
            Some(value) => {
                output_bits.push( (value.val ^ value.flipped) ^ output_wire.should_trace);
            },
            None => {
            },
        }
    }

    convertBits2Bytes(&output_bits)
}

