use crate::circuit::PlainEvalWire;
use crate::circuit::Sha256Circuit;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::circuit::DoubleGate;
use crate::circuit::OUTPUT_BITS_LEN;
use crate::circuit::SINGLE_BLOCK_BITS_LEN;
use crate::circuit::STATE_INFO_BITS_LEN;

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
pub fn get_padded_bits(bytesLen: usize) -> Vec<bool> {
    let mut message_bits_cnt: u64 = (bytesLen * 8) as u64;

    let mut padding: Vec<u8> = vec![0; bytesLen];
    // Step 2: Append 0x80 (which is 128 in decimal)
    padding.push(0x80);
    // Step 3: Append 0x00 until the message length (in bits) + 64 is a multiple of 512
    while (padding.len() * 8 + 64) % 512 != 0 {
        padding.push(0x00);
    }
    // Step 4: Append the original length as an 8-byte (64-bit) big-endian integer
    padding.extend(&message_bits_cnt.to_be_bytes());

    // Assert that the final message length is a multiple of 512 bits
    assert!(
        (padding.len() * 8) % 512 == 0,
        "Padding did not complete properly!"
    );

    convert_bytes2_bits(&padding)
}

pub fn convert_bytes2_bits(message: &Vec<u8>) -> Vec<bool> {
    let mut bits = vec![false; message.len() * 8];
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
pub fn convertBits2Bytes(bits: &Vec<bool>) -> Vec<u8> {
    assert!(
        bits.len() % 8 == 0,
        "The bits length must be a mulitple of 8!"
    );
    let mut output_bytes: Vec<u8> = Vec::new();
    for i in 0..bits.len() / 8 {
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

pub fn plaintext_block_eval(
    circuit: &mut Sha256Circuit,
    evaluation_map: &mut HashMap<usize, PlainEvalWire>,
    output_bits: &mut Vec<bool>,
) {
    //----------Step-0: Evaluate the single block circuit gate by gate------------//
    for gate in &circuit.extra_gates {
        // let mut input0:bool = false;
        // let mut input1:bool = false;
        match evaluation_map.get(&gate.input0) {
            Some(value) => {
                //this evaluation value might also be flipped
                match evaluation_map.get(&gate.input1) {
                    Some(value1) => {
                        //this evaluation value might also be flipped
                        let mut out: bool = false;
                        let mut out_flipped: bool = false;
                        if gate.gateType {
                            //AND gate
                            let mut real_input0: bool =
                                value.val ^ value.flipped ^ gate.input0_flipped;
                            let mut real_input1: bool =
                                value1.val ^ value1.flipped ^ gate.input1_flipped;
                            out = real_input0 && real_input1;
                        } else {
                            //XOR gate
                            out = value.val ^ value1.val;
                            out_flipped = (value.flipped ^ gate.input0_flipped)
                                ^ (value1.flipped ^ gate.input1_flipped);
                        }
                        evaluation_map.insert(
                            gate.output,
                            PlainEvalWire {
                                val: out,
                                flipped: out_flipped,
                            },
                        );
                    }
                    None => {
                        println!("Input1 wire {} not found!!", gate.input1);
                        break;
                    }
                }
            }
            None => {
                println!("Input0 wire {} not found!!", gate.input0);
                break;
            }
        }
    }
    //Step-1: fetch the final output wires
    for (i, output_wire) in circuit.output_wire_ids.iter().enumerate() {
        let mut real_id: usize = output_wire.id;
        if output_wire.should_trace {
            //A not gate is applied here
            real_id = output_wire.input_id;
        }
        match evaluation_map.get(&real_id) {
            Some(value) => {
                output_bits[i] = (value.val ^ value.flipped) ^ output_wire.should_trace;
            }
            None => {
                println!("Output wire {} not found!!", real_id);
            }
        }
    }
}

pub fn planitext_eval(message: &Vec<u8>, circuit: &mut Sha256Circuit) -> Vec<u8> {
    //-----Step-0: Prepare plaintext values for all input wires from two parties------------//
    let secret_bits = convert_bytes2_bits(message);

    //the overall padded_message with original message bits
    let overall_bits = get_padded_bits(message.len());
    let secret_bits_cnt: usize = secret_bits.len();
    let block_cnt: usize = overall_bits.len() / SINGLE_BLOCK_BITS_LEN;

    let mut last_evaluation_result: Vec<bool> = vec![false; OUTPUT_BITS_LEN];
    for i in 0..block_cnt {
        println!("Start to process block {}", i);
        // It stores every k-v: wire_number - evaluation results
        let mut evaluation_map: HashMap<usize, PlainEvalWire> = HashMap::new();

        //Process the second input: 256 bits state info
        for j in 0..STATE_INFO_BITS_LEN {
            let state_wire_id: usize = SINGLE_BLOCK_BITS_LEN + j;
            if i == 0 {
                evaluation_map.insert(
                    state_wire_id,
                    PlainEvalWire {
                        val: circuit.get_initial_hash(j),
                        flipped: false,
                    },
                );
            } else {
                //accept internal output wire result
                evaluation_map.insert(
                    state_wire_id,
                    PlainEvalWire {
                        val: last_evaluation_result[j],
                        flipped: false,
                    },
                );
            }
        }

        //Process the first input: 512 bits block
        let mut extra_double_gates: Vec<DoubleGate> = Vec::new();
        let left_start_index: usize = i * SINGLE_BLOCK_BITS_LEN;
        let right_end_index: usize = (i + 1) * SINGLE_BLOCK_BITS_LEN;
        for j in left_start_index..right_end_index {
            let circuit_wire_id: usize = SINGLE_BLOCK_BITS_LEN - 1 - (j % SINGLE_BLOCK_BITS_LEN);

            if j < secret_bits_cnt {
                //real secret bits input
                let gate = DoubleGate {
                    input0: circuit.extra_input_wire + 2 * j,
                    input1: circuit.extra_input_wire + 2 * j + 1,
                    output: circuit_wire_id,
                    input0_flipped: false,
                    input1_flipped: false,
                    gateType: false,
                };
                evaluation_map.insert(
                    gate.input0,
                    PlainEvalWire {
                        val: secret_bits[j],
                        flipped: false,
                    },
                ); //party-0 input
                evaluation_map.insert(
                    gate.input1,
                    PlainEvalWire {
                        val: false,
                        flipped: false,
                    },
                ); //party-1 input
                extra_double_gates.push(gate);
            } else {
                //padding bits
                evaluation_map.insert(
                    circuit_wire_id,
                    PlainEvalWire {
                        val: overall_bits[j],
                        flipped: false,
                    },
                ); //party-1 input
            }
        }
        //update circuit gates
        circuit.update_extra_circuit(&extra_double_gates);
        plaintext_block_eval(circuit, &mut evaluation_map, &mut last_evaluation_result);
    }

    last_evaluation_result.reverse();
    convertBits2Bytes(&last_evaluation_result)
}
