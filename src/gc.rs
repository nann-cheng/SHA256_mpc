use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use std::ops::Index;
use std::ops::BitXor;
use std::ops::BitXorAssign;

use std::collections::HashMap;
use std::collections::VecDeque;
use crate::circuit::Sha256Circuit;

use std::fmt::{Debug, Formatter, Result as FmtResult};
use aes::{Aes128, BlockEncrypt, NewBlockCipher};
use aes::cipher::generic_array::{GenericArray, ArrayLength};
use crate::utils::convertBytes2Bits;
use crate::utils::convertBits2Bytes;
use crate::circuit::DoubleGate;
use typenum::U16;

/// A 128-bit wire label (same size as an AES block).
pub const LABEL_SECURITY_LEVEL: usize = 16;


#[derive(Clone,Debug, Copy, PartialEq, Eq)]
pub struct WireLabel([u8; LABEL_SECURITY_LEVEL]);

impl WireLabel {
    // Method to create a new WireLabel from an existing array
    pub fn from_data(existing: [u8; LABEL_SECURITY_LEVEL]) -> Self {
        WireLabel(existing) // Use the existing array to initialize the new WireLabel
    }

    pub fn zero() -> Self {
        WireLabel([0; LABEL_SECURITY_LEVEL])
    }

    // Conversion method to GenericArray
    pub fn to_generic_array(&self) -> GenericArray<u8, U16> {
        // Create a GenericArray from the inner array
        GenericArray::from(self.0)
        // GenericArray::from_slice(&self.0)
    }

    pub fn reset_lsb(&mut self){
        self.0[LABEL_SECURITY_LEVEL-1] |= 1;
    }

    pub fn check_lsb(&self)-> bool{
        (self.0[LABEL_SECURITY_LEVEL-1] & 1) == 1
    }
}

impl Index<usize> for WireLabel {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index] // Access the inner array
    }
}

impl BitXor for WireLabel {
    type Output = WireLabel;

    fn bitxor(self, other: WireLabel) -> WireLabel {
        let mut result = [0; LABEL_SECURITY_LEVEL];
        for i in 0..LABEL_SECURITY_LEVEL {
            result[i] = self.0[i] ^ other.0[i]; // XOR each byte
        }
        WireLabel(result)
    }
}

// // Implementing BitXorAssign for WireLabel
impl BitXorAssign for WireLabel {
    fn bitxor_assign(&mut self, other: WireLabel) {
        for i in 0..LABEL_SECURITY_LEVEL {
            self.0[i] ^= other.0[i]; // XOR assign each byte
        }
    }
}

#[derive(Clone,Debug)]
pub struct EvalWire{
    pub label: WireLabel,//if flipped is true, the actual label should be R \xor the stored label
    pub flipped: bool,
}

/// A full garbled circuit structure:
/// - We’ll assume it’s just a list of half-gate AND gates, plus usage of free XOR.
/// - Real circuits might have many gates of different types, wire indexing, etc.
#[derive(Debug)]
pub struct GarbledCircuit {
    pub prf:Aes128,
    pub cur_idx:usize,
    pub rng:rand::rngs::ThreadRng,
    pub global_R:WireLabel,
}

/// The garble table of each AND gate: 
pub struct GarbleAnd {
    pub T_G: WireLabel,
    pub T_E: WireLabel,
}

impl GarbledCircuit {
    pub fn new() -> Self {
        let seed = b"I-am-a-random-seed-a-random-seed";
        // [0u8; 32]; // 32 bytes for a 256-bit seed (you can choose any seed bytes)
        // let mut rng = StdRng::from_seed(*seed);

        const FIXED_AES_KEY: [u8; 16] = [
            0xa5, 0x4f, 0xf5, 0x3a, // H[3]
            0x51, 0x0e, 0x52, 0x7f, // H[4]
            0x9b, 0x05, 0x68, 0x8c, // H[5]
            0x1f, 0x83, 0xd9, 0xab, // H[6]
        ];

        let mut m_rng = rand::thread_rng();
        let mut empty_global_R = [0u8;LABEL_SECURITY_LEVEL];
        m_rng.fill(&mut empty_global_R);
        let mut global:WireLabel = WireLabel(empty_global_R);
        global.reset_lsb(); // guarantee the LSB (least significant bit)to be 1

        // println!("Debug: global R is {:?}", global);

        GarbledCircuit {
            prf: Aes128::new(GenericArray::from_slice(&FIXED_AES_KEY)),
            cur_idx: 0,
            rng:m_rng,
            global_R:global,
        }
    }

    fn next_index(&mut self) -> usize{
        self.cur_idx += 1;
        self.cur_idx
    }

    //A PRF update procedure.
    fn prf_update(&self, label:&WireLabel, tweak:u64) -> WireLabel {
         // Prepare a mutable block for encryption
        let mut block = label.to_generic_array();
        // XOR the tweak into the last 8 bytes (very naive):
        let tweak_bytes = tweak.to_le_bytes();
        for i in 0..8 {
            block[8 + i] ^= tweak_bytes[i];
        }
        self.prf.encrypt_block(&mut block);

        WireLabel(block.into())
    }

    fn evaluate_XOR_gate(&self,zero_label_map: &mut HashMap<usize, EvalWire>, gate:&DoubleGate){
        let mut new_label:WireLabel;
        let mut new_flipped:bool=false;
        //I merged the (out-in wire) two flipped bits
        match zero_label_map.get(&gate.input0) {
            Some(eval_wire) => {
                new_label = eval_wire.label.clone();
                new_flipped = eval_wire.flipped ^ gate.input0_flipped;//merge output-input flipped states
                match zero_label_map.get(&gate.input1) {
                    Some(eval_wire1) => {
                        new_label ^= eval_wire1.label;
                        new_flipped ^= eval_wire1.flipped ^ gate.input1_flipped;
                        zero_label_map.insert(gate.output, EvalWire{label: new_label, flipped: new_flipped} );
                    },
                    None => {
                        println!("Key {} not found when fetch XOR gate input1", gate.input1);
                    },
                }
            },
            None => {
                println!("Key {} not found when fetch XOR gate input0", gate.input0);
            },
        }
    }

    //Assume party 0 as the garbler, he holds his partial inputs and the public circuit
    pub fn garble_circuit(&mut self, circuit:& Sha256Circuit, zero_label_map:&mut HashMap<usize, EvalWire>)-> Vec<GarbleAnd>{
        let mut garbled_vec: Vec<GarbleAnd> = Vec::new();
        for gate in &circuit.extra_gates {
           
            if gate.gateType{//AND
                let j:u64 = self.next_index() as u64;
                let j_prime:u64 = self.next_index() as u64;

                //zero, one labels respectively for input wrie 0
                let mut wa_0 = WireLabel([0; LABEL_SECURITY_LEVEL]);
                let mut wa_1 = WireLabel([0; LABEL_SECURITY_LEVEL]);

                //zero, one labels respectively for input wrie 1
                let mut wb_0 = WireLabel([0; LABEL_SECURITY_LEVEL]);
                let mut wb_1 = WireLabel([0; LABEL_SECURITY_LEVEL]);
                match zero_label_map.get(&gate.input0) {
                    Some(eval_wire) => {
                        let final_flipped:bool = eval_wire.flipped ^ gate.input0_flipped;
                        if final_flipped{
                            wa_1 = eval_wire.label;
                            wa_0 = wa_1 ^ self.global_R;
                        }else{
                            wa_0 = eval_wire.label;
                            wa_1 =  wa_0 ^ self.global_R;
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch AND gate input0", gate.input0);
                        break;
                    },
                }
                match zero_label_map.get(&gate.input1) {
                    Some(eval_wire) => {
                        let final_flipped:bool = eval_wire.flipped ^ gate.input1_flipped;
                        if final_flipped{
                            wb_1 = eval_wire.label;
                            wb_0 = wb_1 ^ self.global_R;
                        }else{
                            wb_0 = eval_wire.label;
                            wb_1 =  wb_0 ^ self.global_R;
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch  AND gate input1", gate.input1);
                        break;
                    },
                }
                //make garbled table from here, firstly update zero_label depending on flipped state
               let p_a:bool = wa_0.check_lsb();//input wire 0 permutation bit
               let p_b:bool = wb_0.check_lsb(); //input wire 1 permutation bit
                
                //step-0: First half gate
                let mut wa_0_enc = self.prf_update(&wa_0, j);
                let mut T_G:WireLabel = wa_0_enc ^ self.prf_update(&wa_1, j);
                if p_b{ T_G ^= self.global_R; }
                 // Step 1: Calculate W_G
                let mut WG_0: WireLabel = wa_0_enc;
                if p_a{  WG_0 ^= T_G;   }

                // Step 2: Second half gate
                let mut wb_0_enc = self.prf_update(&wb_0, j_prime);
                let mut T_E: WireLabel = wb_0_enc ^ self.prf_update(&wb_1, j_prime) ^ wa_0;
                let mut  WE_0: WireLabel = wb_0_enc;
                if p_b{ WE_0 ^= wa_0 ^ T_E; }

                //Returning the output values
                garbled_vec.push(GarbleAnd{ T_G: T_G, T_E: T_E});

                //I Should set the flipped bit here as false, because AND gate renews everything
                zero_label_map.insert(gate.output, EvalWire{label:  WG_0 ^ WE_0, flipped: false} );
            }else{//FREE XOR, need to compute the output zero label
                self.evaluate_XOR_gate(zero_label_map, gate);
            }
        }
        garbled_vec
    }

    //  Assume party 1 as the evaluator
    /// Evaluate the entire circuit on (input wire labels) assuming it has all input wire labels.
    /// Returns final output bits (one label per output wire).
    pub fn evaluate(&mut self, circuit:&Sha256Circuit, garbled_gates:&mut VecDeque<GarbleAnd>, evaluate_label_map:&mut HashMap<usize, WireLabel>){
        for gate in &circuit.extra_gates {
            if gate.gateType{//AND
                //a random evaluated label for input wrie 0,1
                match evaluate_label_map.get(&gate.input0) {
                    Some(eval_wire) => {
                        let wa:WireLabel = eval_wire.clone();
                        match evaluate_label_map.get(&gate.input1) {
                            Some(eval_wire1) => {
                                let wb:WireLabel = eval_wire1.clone();
                                //decrypt garbled table from here
                                let s_a:bool = wa.check_lsb();//input wire 0 permutation bit
                                let s_b:bool = wb.check_lsb();//input wire 1 permutation bit
                                //step-0: First half gate
                                if let Some(garbled) = garbled_gates.pop_front() {
                                    let mut T_G:WireLabel = garbled.T_G;
                                    let mut T_E:WireLabel = garbled.T_E;
                                    //Step 1: Calculate W_G
                                    let j = self.next_index() as u64;
                                    let j_prime = self.next_index() as u64;
                                    let mut WG: WireLabel = self.prf_update(&wa,  j);
                                    if s_a{  WG ^= T_G;   }
                                    // Step 2: Second half gate
                                    let mut WE: WireLabel = self.prf_update(&wb, j_prime);
                                    if s_b{ WE ^= wa ^ T_E; }
                                    evaluate_label_map.insert(gate.output, WG ^ WE );
                                }
                            },
                            None => {
                                println!("Key {} not found when fetch  AND gate input1", gate.input1);
                            },
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch AND gate input0", gate.input0);
                    },
                }
            }else{
                //FREE XOR, need to evaluate the output label
                match evaluate_label_map.get(&gate.input0) {
                    Some(eval_wire) => {
                        let mut new_label = eval_wire.clone();
                        match evaluate_label_map.get(&gate.input1) {
                            Some(eval_wire1) => {
                                new_label ^= eval_wire1.clone();
                                evaluate_label_map.insert(gate.output, new_label );
                            },
                            None => {
                                println!("Key {} not found when fetch XOR gate input1", gate.input1);
                            },
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch XOR gate input0", gate.input0);
                    },
                }
            }
        }
    }
}