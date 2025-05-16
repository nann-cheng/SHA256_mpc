use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};

use crate::utils::convert_bytes2_bits;

pub const INITIAL_HASH_VALUES: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, // H[0]
    0xbb, 0x67, 0xae, 0x85, // H[1]
    0x3c, 0x6e, 0xf3, 0x72, // H[2]
    0xa5, 0x4f, 0xf5, 0x3a, // H[3]
    0x51, 0x0e, 0x52, 0x7f, // H[4]
    0x9b, 0x05, 0x68, 0x8c, // H[5]
    0x1f, 0x83, 0xd9, 0xab, // H[6]
    0x5b, 0xe0, 0xcd, 0x19, // H[7]
];

pub const SINGLE_BLOCK_BITS_LEN: usize = 512;
pub const STATE_INFO_BITS_LEN: usize = 256;
pub const OUTPUT_BITS_LEN: usize = 256;
pub const AND_GATES_CNT: usize = 22573;

#[derive(Debug, Copy, Clone)]
pub struct XorAndGate {
    pub input0: usize,
    pub input1: usize,
    pub output: usize,

    pub input0_flipped: bool,
    pub input1_flipped: bool,

    pub gate_type: bool, //false: XOR gate, true; AND gate
}

#[derive(Debug)]
pub struct OutputWire {
    pub id: usize,
    pub input_id: usize,
    pub should_trace: bool,
}

// #[derive(Debug)]
// pub struct PlainEvalWire {
//     pub val: bool,
//     pub flipped: bool,
// }

#[derive(Debug)]
pub struct Sha256Circuit {
    pub initial_hash_vec: Vec<bool>,
    pub extra_input_wire: usize,
    pub gates: Vec<XorAndGate>,
    pub extra_gates: Vec<XorAndGate>, //mpc part input gates, additional XORs

    pub xor_cnt: usize, //Circuit's total xor gates count
    pub and_cnt: usize, //Circuit's total and gates count
    pub inv_cnt: usize, //Circuit's total inv gates count

    pub output_wire_ids: Vec<OutputWire>, //Circuit's output wire start index
}

//This class computes the actual single block circuit for Sha256(x0 XOR x_1), with a input of the message byte length
impl Sha256Circuit {
    pub fn new() -> io::Result<Self> {
        let file = File::open("data/sha256-bristol-basic.txt")?;
        let reader = io::BufReader::new(file);
        //Initialize the vector to hold all (XorAndGate gates) (including NOT gate)
        let mut xor_and_gates: Vec<XorAndGate> = Vec::new();
        //Stores all (not gates) but in reverse order {w_out,w_in}
        let mut inv_gates_map: HashMap<usize, usize> = HashMap::new();

        //Read lines from the file
        let mut xor_cnt: usize = 0;
        let mut and_cnt: usize = 0;
        let mut inv_cnt: usize = 0;
        let mut extra_input_wire: usize = 0;

        let mut line_number: usize = 0;
        for line_result in reader.lines() {
            line_number += 1;
            let line = line_result?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if line_number == 1 {
                extra_input_wire = parts[1].parse().unwrap();
            } else if line_number >= 5 {
                if parts.len() == 6 {
                    //XorAndGate type
                    let gate = XorAndGate {
                        input0: parts[2].parse().unwrap(),
                        input1: parts[3].parse().unwrap(),
                        output: parts[4].parse().unwrap(),
                        input0_flipped: false,
                        input1_flipped: false,
                        gate_type: parts[5] == "AND",
                    };
                    if !gate.gate_type {
                        xor_cnt += 1; // Increment xor_cnt if gate.gate_type is false
                    } else {
                        and_cnt += 1; // Increment and_cnt if gate.gate_type is true
                    }
                    xor_and_gates.push(gate);
                } else {
                    //NOT gate type
                    let input: usize = parts[2].parse().unwrap();
                    let output: usize = parts[3].parse().unwrap();
                    inv_cnt += 1;
                    inv_gates_map.insert(output, input);
                }
            }
        }

        let mut fina_output_wires: Vec<OutputWire> = Vec::new();
        for i in 0..256 {
            fina_output_wires.push(OutputWire {
                id: extra_input_wire - OUTPUT_BITS_LEN + i,
                input_id: 0,
                should_trace: false,
            });
        }

        Self::mark_double_gates(&inv_gates_map, &mut xor_and_gates, &mut fina_output_wires);

        let mut reversed_hash_vec = convert_bytes2_bits(INITIAL_HASH_VALUES.as_ref());
        reversed_hash_vec.reverse();
        Ok(Sha256Circuit {
            initial_hash_vec: reversed_hash_vec,
            extra_input_wire,
            gates: xor_and_gates,
            extra_gates: Vec::new(),

            xor_cnt,
            and_cnt,
            inv_cnt,
            output_wire_ids: fina_output_wires,
        })
    }

    pub fn get_initial_hash(&self, idx: usize) -> bool {
        assert!(
            (0..=STATE_INFO_BITS_LEN - 1).contains(&idx),
            "Input index is not in range [0,256)"
        );

        self.initial_hash_vec[idx]
    }

    pub fn update_extra_circuit(&mut self, extra_gates: &[XorAndGate]) {
        self.extra_gates = Vec::new();
        if !extra_gates.is_empty() {
            self.extra_gates.extend(extra_gates.iter().cloned());
        }
        self.extra_gates.extend(self.gates.iter().cloned());
    }

    //from not Gates mapping, add not marks onto associated double gates
    //process every input wire, if it's the output of an And gate, mark flip bit as true
    fn mark_double_gates(
        inv_gates: &HashMap<usize, usize>,
        xor_and_gates: &mut [XorAndGate],
        output_wire_ids: &mut Vec<OutputWire>,
    ) {
        for gate in xor_and_gates.iter_mut() {
            let mut tmp_input0: usize = gate.input0;
            let mut flip_bit0: bool = false;
            let mut tmp_input1: usize = gate.input1;
            let mut flip_bit1: bool = false;

            while let Some(&value) = inv_gates.get(&tmp_input0) {
                tmp_input0 = value;
                flip_bit0 = !flip_bit0;
            }
            while let Some(&value) = inv_gates.get(&tmp_input1) {
                tmp_input1 = value;
                flip_bit1 = !flip_bit1;
            }

            gate.input0 = tmp_input0;
            gate.input1 = tmp_input1;
            gate.input0_flipped = flip_bit0;
            gate.input1_flipped = flip_bit1;
        }

        //Why need to process output_ids? they may come after a not gate, these wires are never processed (as last layers, never as input to gate) move the output ids directly to xor_and_gates, this is to remove last layer outputs
        //this specially marked output wire that is deriving from a not gate, because they are currently ignored by gate evaluation
        for output_wire in output_wire_ids {
            match inv_gates.get(&output_wire.id) {
                //If output id is the output wire of a not gate
                Some(&input_id) => {
                    //find the specified gate in self.gates and change the internal data
                    for gate in xor_and_gates.iter_mut().rev() {
                        //Reverse iterate using into_iter() and rev()
                        if input_id == gate.output {
                            output_wire.input_id = input_id;
                            output_wire.should_trace = true; //should flip this output wire when reconstructing
                                                             // println!("output_wire changed; {} --> {}",output_wire.id, gate.output);
                            break;
                        }
                    }
                }
                None => {}
            }
        }
    }

    pub fn display(&self) {
        println!("The single block sha256 Boolean circuit has:\n");
        println!(" {} XOR gates", self.xor_cnt);
        println!(" {} AND gates", self.and_cnt);
        println!(" {} INV gates", self.inv_cnt);
    }
}
