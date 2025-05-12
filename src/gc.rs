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
const LABEL_SECURITY_LEVEL: usize = 16;


#[derive(Clone,Debug, Copy, PartialEq, Eq)]
pub struct WireLabel([u8; LABEL_SECURITY_LEVEL]);

impl WireLabel {
    // Conversion method to GenericArray
    pub fn to_generic_array(&self) -> GenericArray<u8, U16> {
        // Create a GenericArray from the inner array
        GenericArray::from(self.0)
        // GenericArray::from_slice(&self.0)
    }

    pub fn flip_last_bit(&mut self){
        self.0[LABEL_SECURITY_LEVEL-1] |= 1;
    }

    pub fn check_last_bit(&self)-> bool{
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
}

/// The garble table of each AND gate: 
pub struct GarbleAnd {
    pub T_G: WireLabel,
    pub T_E: WireLabel,
}

pub struct GarbleResult{
    pub p0_label0: Vec<WireLabel>,//label0 corrsponding to p0's real input bits
    pub p1_labels: Vec<WireLabel>,//a pair of messages: (rnd, rand \xor R)
    pub garbled_and: Vec<GarbleAnd>,//all AND gates's garbled result
    pub permu_bits: Vec<bool>,//Final output wire's permutation bits
}

 // 4b1c2f3e0d8a6f2b9c3e0a1f4b8d5e6f8c1f0a2b3e4d5c6b7e8f0a1b2c3d4e5
impl GarbledCircuit {
    pub fn new() -> Self {
        let seed = b"I-am-a-random-seed-a-random-seed";
        // [0u8; 32]; // 32 bytes for a 256-bit seed (you can choose any seed bytes)
        let mut rng = StdRng::from_seed(*seed);

        const FIXED_AES_KEY: [u8; 16] = [
            0xa5, 0x4f, 0xf5, 0x3a, // H[3]
            0x51, 0x0e, 0x52, 0x7f, // H[4]
            0x9b, 0x05, 0x68, 0x8c, // H[5]
            0x1f, 0x83, 0xd9, 0xab, // H[6]
        ];
        // let key: GenericArray<u8, U16> = GenericArray::from_slice(&FIXED_AES_KEY);
        let m_prf = Aes128::new(GenericArray::from_slice(&FIXED_AES_KEY));

        GarbledCircuit {
            prf: m_prf,
            cur_idx: 0,
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
        // This is only a placeholder to show "some" usage of a tweak.
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
    pub fn garble(&mut self, message:&Vec<u8>, circuit:&Sha256Circuit)-> GarbleResult{
        // let mut rng = rand::thread_rng();

        let seed = [0u8; 32]; // Use a fixed seed (32 bytes for StdRng)
        let mut rng = StdRng::from_seed(seed);

        let mut empty_global_R = [0u8;LABEL_SECURITY_LEVEL];
        rng.fill(&mut empty_global_R);

        let mut global_R:WireLabel = WireLabel(empty_global_R);
        global_R.flip_last_bit(); // Set the LSB of the last bit to 1

        println!("Debug: global R is {:?}", global_R);


        //-----Step-0: generate random input wire labels------------//
        let p0_input_cnt:usize = circuit.input_wires_0.len();

        //Generate a random array of bytes
        let label_size:usize = p0_input_cnt + circuit.input_wires_1.len();
         let mut zero_labels: Vec<WireLabel> = Vec::with_capacity(label_size);
         for _ in 0..label_size{
            let mut label = [0u8; 16];
            // Fill the label's 16 bytes with random data
            rng.fill(&mut label);
            zero_labels.push(WireLabel(label));
         }

        let bits = convertBytes2Bits(message);
        let mut p0_vec: Vec<WireLabel> = Vec::new();//Prepare P0's pseudorandom label for transmission
        for i in 0..p0_input_cnt{
            if bits[i]{
                p0_vec.push( zero_labels[i] ^ global_R );
            }else{
                p0_vec.push( zero_labels[i] );
            }
        }
        let mut p1_ot_vec: Vec<WireLabel> = Vec::new();// Prepare P1's OT message pair (zero-lable, one-lable) list
        for i in 0..circuit.input_wires_1.len(){
            p1_ot_vec.push(  zero_labels[p0_input_cnt + i] );//define this as the zero label
            p1_ot_vec.push(  zero_labels[p0_input_cnt + i] ^ global_R );
        }

        //-----Step-1: Prepare garbled circuit gate by gate of the circuit (gc)------------//
        //compute zero-labels for every wire (with flipped state because of internal Non gate )
        //A EvalWire structure with with flipped state is chosen, as though input wires are by default false, internal out gates can be marked as flipped=true, thus, we universally store EvalWire type for convenince use
        let mut zero_label_map: HashMap<usize, EvalWire> = HashMap::new();
        for i in 0..circuit.input_wires_0.len(){
            zero_label_map.insert( circuit.input_wires_0[i], EvalWire{label: zero_labels[i], flipped: false});
        }
        for i in 0..circuit.input_wires_1.len(){
            zero_label_map.insert( circuit.input_wires_1[i], EvalWire{label: zero_labels[p0_input_cnt+i], flipped: false} );
        }
        //Set public input wire part as zero for convenience
        for wire in &circuit.public_input_wires{
            zero_label_map.insert( wire.id,  EvalWire{label:  WireLabel([0; LABEL_SECURITY_LEVEL]), flipped: wire.bit } );
        }

        let mut garbled_vec: Vec<GarbleAnd> = Vec::new();
        let mut output_permutation_bits: Vec<bool> = Vec::new();

        //Step-1: Garble the entire circuit
        // let mut debug_cnt:usize=0;
        for gate in &circuit.gates {
           
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
                            wa_0 = wa_1 ^ global_R;
                        }else{
                            wa_0 = eval_wire.label;
                            wa_1 =  wa_0 ^ global_R;
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch AND gate input0", gate.input0);
                    },
                }
                match zero_label_map.get(&gate.input1) {
                    Some(eval_wire) => {
                        let final_flipped:bool = eval_wire.flipped ^ gate.input1_flipped;
                        if final_flipped{
                            wb_1 = eval_wire.label;
                            wb_0 = wb_1 ^ global_R;
                        }else{
                            wb_0 = eval_wire.label;
                            wb_1 =  wb_0 ^ global_R;
                        }
                    },
                    None => {
                        println!("Key {} not found when fetch  AND gate input1", gate.input1);
                    },
                }
                //make garbled table from here, firstly update zero_label depending on flipped state
               let p_a:bool = wa_0.check_last_bit();//input wire 0 permutation bit
               let p_b:bool = wb_0.check_last_bit(); //input wire 1 permutation bit
                
                //TODO: Optimize the call to H call 
                //step-0: First half gate
                let mut T_G:WireLabel = self.prf_update(&wa_0, j) ^ self.prf_update(&wa_1, j);
                if p_b{ T_G ^= global_R; }
                 // Step 1: Calculate W_G
                let mut WG_0: WireLabel = self.prf_update(&wa_0, j);
                if p_a{  WG_0 ^= T_G;   }

                // Step 2: Second half gate
                let mut T_E: WireLabel = self.prf_update(&wb_0, j_prime) ^ self.prf_update(&wb_1, j_prime) ^ wa_0;
                let mut  WE_0: WireLabel = self.prf_update(&wb_0, j_prime);
                if p_b{ WE_0 ^= wa_0 ^ T_E; }

                //Returning the output values
                garbled_vec.push(GarbleAnd{ T_G: T_G, T_E: T_E});

                //I Should set the flipped bit here as false, because AND gate renews everything
                zero_label_map.insert(gate.output, EvalWire{label:  WG_0 ^ WE_0, flipped: false} );
            }else{//FREE XOR, need to compute the output zero label
                // debug_cnt+=1;
                self.evaluate_XOR_gate(&mut zero_label_map, gate);
            }
        }

        //Manage output (just output the final permutation bit for label 0)
        for (i, output_wire) in circuit.output_wire_ids.iter().enumerate() {
            let mut real_id:usize = output_wire.id;
            if output_wire.should_trace{//A not gate is applied here
                real_id = output_wire.input_id;
            }
            match zero_label_map.get( &real_id ){
                Some(wire) => {
                    let mut output_p_bit:bool = wire.label.check_last_bit();
                    output_p_bit ^= wire.flipped;

                    output_permutation_bits.push(output_p_bit);//This should be the real output wire zero label last bit
                },
                None => {
                },
            }
        }
       let ret=GarbleResult{
            p0_label0: p0_vec,
            p1_labels: p1_ot_vec,
            garbled_and: garbled_vec,
            permu_bits: output_permutation_bits,
       };
       ret
    }

    //  Assume party 1 as the evaluator
    /// Evaluate the entire circuit on (input wire labels) assuming it has all input wire labels.
    /// Returns final output bits (one label per output wire).
    pub fn evaluate(&mut self, circuit:&Sha256Circuit, input_wire_labels:&Vec<WireLabel>, garbled_gates:&mut VecDeque<GarbleAnd>, output_permutation_bits:& Vec<bool>) -> Vec<u8> {
        //Step-0: Initiate assigned zero labels from input wires
        let mut evaluate_label_map: HashMap<usize, WireLabel> = HashMap::new();
        let input_bits_cnt:usize = circuit.input_wires_0.len();
        for i in 0..input_bits_cnt{
            evaluate_label_map.insert( circuit.input_wires_0[i], input_wire_labels[i]);
            evaluate_label_map.insert( circuit.input_wires_1[i], input_wire_labels[input_bits_cnt+i] );
        }
        //Set public input wire part as zero for convenience
        for wire in &circuit.public_input_wires{
            evaluate_label_map.insert( wire.id,  WireLabel([0; LABEL_SECURITY_LEVEL]) );
        }

        for gate in &circuit.gates {
            if gate.gateType{//AND
                //a random evaluated label for input wrie 0,1
                match evaluate_label_map.get(&gate.input0) {
                    Some(eval_wire) => {
                        let wa:WireLabel = eval_wire.clone();
                        match evaluate_label_map.get(&gate.input1) {
                            Some(eval_wire1) => {
                                let wb:WireLabel = eval_wire1.clone();
                                //decrypt garbled table from here
                                let s_a:bool = wa.check_last_bit();//input wire 0 permutation bit
                                let s_b:bool = wb.check_last_bit();//input wire 1 permutation bit
                                //TODO: Optimize call to H only once 
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
                                    //I Should set the flipped bit here as false, because AND gate renews everything
                                    evaluate_label_map.insert(gate.output,   WG ^ WE );
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

        //This output logic could be clearly worked out: extract real bit by decrypting label from permutation bit
        let mut output_bits: Vec<bool> = Vec::new();
        //Manage output (just output the final permutation bit for label 0)
        for (i, output_wire) in circuit.output_wire_ids.iter().enumerate() {
            let mut out_bit:bool= output_permutation_bits[i];

            let mut real_id:usize = output_wire.id;

            if output_wire.should_trace{//A not gate is applied here
                real_id = output_wire.input_id;
                out_bit ^= true;
            }
            match evaluate_label_map.get( &real_id ) {
                Some(wire) => {
                    out_bit ^= wire.check_last_bit();
                    output_bits.push(out_bit);
                },
                None => {
                },
            }
        }
        convertBits2Bytes(&output_bits)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_garbled_circuit_skeleton() {
    }
}