use crate::utils::convertBits2Bytes;
use crate::utils::convertBytes2Bits;
use crate::utils::get_padded_bits;

use crate::gc::EvalWire;
use crate::gc::WireLabel;
use crate::gc::GarbleAnd;
use crate::gc::LABEL_SECURITY_LEVEL;
use crate::GarbledCircuit;

use std::collections::VecDeque;
use std::collections::HashMap;

use crate::circuit::SINGLE_BLOCK_BITS_LEN;
use crate::circuit::STATE_INFO_BITS_LEN;
use crate::circuit::OUTPUT_BITS_LEN;
use crate::circuit::AND_GATES_CNT;
use crate::circuit::DoubleGate;
use crate::circuit::Sha256Circuit;
use rand::Rng;
use std::io;

pub struct GarbleResult{
    pub p0_labels: Vec<WireLabel>,//label0 corrsponding to p0's real input bits
    pub p1_labels: Vec<WireLabel>,//a pair of messages: (rnd, rand \xor R)

    pub garbled_and: Vec<GarbleAnd>,//all AND gates's garbled result
    pub permu_bits: Vec<bool>,//Final output wire's permutation bits
}


//generate the whol sha256 circuit
#[derive(Debug)]
pub struct Party{
    pub id: usize,//0 or 1 (garbler or evaluator)
    secret_bits: Vec<bool>,
    circuit:Sha256Circuit,
}

impl Party {
    // Create a new party 
    pub fn new(role:usize, message:&Vec<u8>) -> io::Result<Self> {
        let m_circuit = Sha256Circuit::new(message.len())
            .map_err(|e| {
                println!("Failed to create circuit: {}", e);
                io::Error::new(io::ErrorKind::Other, "Circuit creation failed")
            })?;
        
        if role==0{ //server as garbler
            m_circuit.display();
        }else{//client as evaluator
        }


        // Return the new Party instance
        Ok(Party{
            id:role,
            // network:network_interface,
            secret_bits: convertBytes2Bits(message).to_vec(),
            circuit: m_circuit,
        })
    }
    
    pub fn send_XOR_bits(&self){
    }

    pub fn start_garbling(&mut self) -> GarbleResult{
        let mut garbler = GarbledCircuit::new();

        let secret_bits_cnt:usize = self.secret_bits.len();
        //-----Step-0: generate random input wire labels------------//
        let label_size:usize = secret_bits_cnt*2;
        let mut zero_labels: Vec<WireLabel> = Vec::with_capacity(label_size);
        for _ in 0..label_size{
            let mut label = [0u8; 16];
            garbler.rng.fill(&mut label);// Fill the label's 16 bytes with random data
            zero_labels.push( WireLabel::from_data(label) );
        }

        //-----Step-1: Prepare garbled circuit gate by gate of the circuit (gc)------------//
        //compute zero-labels for every wire (with flipped state because of internal Non gate )
        //A EvalWire structure with with flipped state is chosen, as though input wires are by default false, internal out gates can be marked as flipped=true, thus, we universally store EvalWire type for convenince use
        let mut p0_vec: Vec<WireLabel> = Vec::with_capacity(secret_bits_cnt);//Prepare P0's pseudorandom label for transmission
        let mut p1_ot_vec: Vec<WireLabel> = Vec::with_capacity(secret_bits_cnt*2);// Prepare P1's OT message pair (zero-lable, one-lable) list
        for j in 0..secret_bits_cnt{
            if self.secret_bits[j]{
                p0_vec.push( zero_labels[j] ^ garbler.global_R );
            }else{
                p0_vec.push( zero_labels[j] );
            }
              p1_ot_vec.push(  zero_labels[secret_bits_cnt + j] );//define this as the zero label
            p1_ot_vec.push(  zero_labels[secret_bits_cnt + j] ^ garbler.global_R );
        }
        let mut all_garbled_ands: Vec<GarbleAnd> = Vec::new();
        let mut output_permutation_bits: Vec<bool> = Vec::new();


        let overall_bits = get_padded_bits(secret_bits_cnt/8);
        let block_cnt:usize = overall_bits.len()/SINGLE_BLOCK_BITS_LEN;
        let mut last_evaluation_result: Vec<EvalWire>  = Vec::with_capacity(OUTPUT_BITS_LEN);
        for i in 0..OUTPUT_BITS_LEN{
            last_evaluation_result.push( EvalWire{label:  WireLabel::zero(), flipped: false } );
        }

        for i in 0..block_cnt{
            
            
            // It stores every k-v: wire_number - evaluation results
            let mut zero_label_map: HashMap<usize, EvalWire> = HashMap::new();

            //Process the first input: 512 bits block
            let mut extra_double_gates : Vec<DoubleGate> = Vec::new();

            let left_start_index:usize = i*SINGLE_BLOCK_BITS_LEN;
            let right_end_index:usize = (i+1)*SINGLE_BLOCK_BITS_LEN;

            for j in left_start_index..right_end_index{
                let circuit_wire_id:usize = SINGLE_BLOCK_BITS_LEN - 1 - (j%SINGLE_BLOCK_BITS_LEN);
                if j < secret_bits_cnt {//real secret bits input
                    let gate = DoubleGate {
                                    input0: self.circuit.extra_input_wire + 2*j,
                                    input1: self.circuit.extra_input_wire + 2*j +1,
                                    output: circuit_wire_id,
                                    input0_flipped: false,
                                    input1_flipped: false,
                                    gateType: false,
                                };
                    zero_label_map.insert(gate.input0, EvalWire{ label:zero_labels[j], flipped: false} );//party-0 zero_label
                    zero_label_map.insert(gate.input1, EvalWire{ label:zero_labels[secret_bits_cnt+ j ], flipped: false} );//party-1 zero_label
                    extra_double_gates.push(gate);
                }else{
                    //padding bits
                    zero_label_map.insert(circuit_wire_id, EvalWire{label: WireLabel::zero(), flipped: overall_bits[j]}  );//public input
                }
            }
            //Process the second input: 256 bits state info
            for j in 0..STATE_INFO_BITS_LEN{
                let state_wire_id:usize =  SINGLE_BLOCK_BITS_LEN + j;
                if i==0{
                    zero_label_map.insert( state_wire_id, EvalWire{label:  WireLabel::zero(), flipped: self.circuit.get_initial_hash(j)} );
                }else{//accept internal output wire result
                    zero_label_map.insert( state_wire_id, last_evaluation_result[j].clone() );
                }
            }
           //update circuit gates
           self.circuit.update_extra_circuit(&extra_double_gates);

           all_garbled_ands.extend( garbler.garble_circuit( &self.circuit, &mut zero_label_map) );

            for (k, output_wire) in self.circuit.output_wire_ids.iter().enumerate(){//final output wires logic
                let mut real_id:usize = output_wire.id;
                if output_wire.should_trace{//A not gate is applied here
                    real_id = output_wire.input_id;
                }
                match zero_label_map.get( &real_id ){
                    Some(wire) => {
                        //derive permutation bits by last block
                        //Manage output (just output the final permutation bit for label 0)
                        if i < block_cnt-1{
                            last_evaluation_result[k] =  EvalWire{label:  wire.label, flipped: output_wire.should_trace ^ wire.flipped };//flip real_input wire to the next round evaluation
                        }else{
                            let mut output_p_bit:bool = wire.label.check_last_bit();
                            output_p_bit ^= wire.flipped;
                            output_permutation_bits.push(output_p_bit);//This should be the real output wire zero label last bit
                        }
                    },
                    None => {
                        println!("Output wire {} not found!!", real_id);
                    },
                }
            }
            println!("Garbler: {}/{} blocks garbled.",i+1,block_cnt);
        }
        
       let ret=GarbleResult{ p0_labels: p0_vec,  p1_labels: p1_ot_vec,
            garbled_and: all_garbled_ands,  permu_bits: output_permutation_bits,
       };
       ret
    }

    pub fn start_evaluating(&mut self, ret:&mut GarbleResult) -> Vec<u8>{
        let mut evaluator = GarbledCircuit::new();
        let secret_bits_cnt:usize = self.secret_bits.len();
        let overall_bits = get_padded_bits(secret_bits_cnt/8);
        let block_cnt:usize = overall_bits.len()/SINGLE_BLOCK_BITS_LEN;
        
        let mut p1_labels: Vec<WireLabel> = Vec::with_capacity(secret_bits_cnt);
         for j in 0..secret_bits_cnt{
            if self.secret_bits[j]{
                p1_labels.push( ret.p1_labels[2*j+1] );
            }else{
                p1_labels.push( ret.p1_labels[2*j] );
            }
        }

        let mut last_evaluation_result: Vec<WireLabel> = vec![ WireLabel::zero(); OUTPUT_BITS_LEN ];
        let mut output_bits: Vec<bool> =  Vec::with_capacity(OUTPUT_BITS_LEN);
        for i in 0..block_cnt{
            // It stores every k-v: wire_number - evaluation results
            let mut evaluate_label_map: HashMap<usize, WireLabel> = HashMap::new();
            //Process the first input: 512 bits block
            let mut extra_double_gates : Vec<DoubleGate> = Vec::new();
            let left_start_index:usize = i*SINGLE_BLOCK_BITS_LEN;
            let right_end_index:usize = (i+1)*SINGLE_BLOCK_BITS_LEN;
            for j in left_start_index..right_end_index{
                let circuit_wire_id:usize = SINGLE_BLOCK_BITS_LEN - 1 - (j%SINGLE_BLOCK_BITS_LEN);
                if j < secret_bits_cnt {//real secret bits input
                    let gate = DoubleGate {
                                    input0: self.circuit.extra_input_wire + 2*j,
                                    input1: self.circuit.extra_input_wire + 2*j +1,
                                    output: circuit_wire_id,
                                    input0_flipped: false,
                                    input1_flipped: false,
                                    gateType: false,
                                };
                    evaluate_label_map.insert(gate.input0, ret.p0_labels[j] );//party-0 real_label
                    evaluate_label_map.insert(gate.input1, p1_labels[j] );//party-1 real_label
                    extra_double_gates.push(gate);
                }else{
                    //padding bits
                    evaluate_label_map.insert(circuit_wire_id,WireLabel::zero());//public garbage input
                }
            }
            //Process the second input: 256 bits state info
            for j in 0..STATE_INFO_BITS_LEN{
                let state_wire_id:usize =  SINGLE_BLOCK_BITS_LEN + j;
                if i==0{
                    evaluate_label_map.insert( state_wire_id, WireLabel::zero());
                }else{//accept internal output wire result
                    evaluate_label_map.insert( state_wire_id, last_evaluation_result[j] );
                }
            }
           //update circuit gates
            self.circuit.update_extra_circuit(&extra_double_gates);

            let cur_garble_vec:Vec<GarbleAnd> = ret.garbled_and.drain(0..AND_GATES_CNT).collect();
            let mut cur_garbled_gates: VecDeque<GarbleAnd> = VecDeque::from(cur_garble_vec);//Convert Vec to VecDeque

            evaluator.evaluate(&self.circuit, &mut cur_garbled_gates, &mut evaluate_label_map);

            for (k, output_wire) in self.circuit.output_wire_ids.iter().enumerate(){//final output logic
                let mut real_id:usize = output_wire.id;
                if output_wire.should_trace{//A not gate is applied here
                    real_id = output_wire.input_id;
                }
                match evaluate_label_map.get( &real_id ){
                    Some(wire) => {
                        //derive permutation bits by last block
                        if i < block_cnt-1{
                            last_evaluation_result[k] = wire.clone();
                        }else{//decrypt output
                            let mut out_bit:bool= ret.permu_bits[k];
                            out_bit ^= wire.check_last_bit();
                            output_bits.push(out_bit);
                        }
                    },
                    None => {
                        println!("Output wire {} not found!!", real_id);
                    },
                }
            }

            println!("Evaluator: {}/{} blocks evaluated.. ", i+1,block_cnt );
        }
        output_bits.reverse();
        convertBits2Bytes(&output_bits)
    }
}
