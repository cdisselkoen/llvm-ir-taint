use llvm_ir::*;
use std::collections::HashMap;

struct TaintState {
    /// Set of `Name`s of variables which are tainted.
    /// That is, a variable is in this set iff we have marked it tainted.
    tainted_vars: HashSet<Name>,
}

impl TaintState {
    /// Return `true` if the given `op` has been marked tainted, otherwise `false`
    fn is_operand_tainted(&self, op: &Operand) -> bool {
        match op {
            Operand::LocalOperand { name, .. } => self.tainted_vars.contains(op),
            Operand::ConstantOperand(_) => false,
            Operand::MetadataOperand => false,
        }
    }

    /// process the given `Instruction`, updating taint marks if appropriate.
    fn process_instruction(&mut self, inst: &Instruction) {
        if inst.is_binary_op() {
            let bop: groups::BinaryOp = inst.try_into().unwrap();
            let should_taint_output = self.is_operand_tainted(bop.get_operand0())
                || self.is_operand_tainted(bop.get_operand1());
            if should_taint_output {
                self.tainted_vars.insert(bop.get_result());
            }
        } else if inst.is_unary_op() {
            let uop: groups::UnaryOp = inst.try_into().unwrap();
            if self.is_operand_tainted(uop.get_operand()) {
                self.tainted_vars.insert(uop.get_result());
            }
        } else {
            match inst {
                Instruction::ExtractElement(ee) => {
                    let should_taint_output = self.is_operand_tainted(&ee.vector)
                        || self.is_operand_tainted(&ee.index);
                    if should_taint_output {
                        self.tainted_vars.insert(ee.get_result());
                    }
                },
                Instruction::InsertElement(ie) => {
                    let should_taint_output = self.is_operand_tainted(&ie.vector)
                        || self.is_operand_tainted(&ie.element)
                        || self.is_operand_tainted(&ie.index);
                    if should_taint_output {
                        self.tainted_vars.insert(ie.get_result());
                    }
                },
                Instruction::ShuffleVector(sv) => {
                    let should_taint_output = self.is_operand_tainted(&sv.operand0)
                        || self.is_operand_tainted(&sv.operand1);
                    if should_taint_output {
                        self.tainted_vars.insert(sv.get_result());
                    }
                },
                Instruction::ExtractValue(ev) => {
                    let should_taint_output = self.is_operand_tainted(&ev.aggregate);
                    if should_taint_output {
                        self.tainted_vars.insert(ev.get_result());
                    }
                },
                Instruction::InsertValue(iv) => {
                    let should_taint_output = self.is_operand_tainted(&iv.aggregate)
                        || self.is_operand_tainted(&iv.element);
                    if should_taint_output {
                        self.tainted_vars.insert(iv.get_result());
                    }
                },
                Instruction::Alloca(alloca) => {
                    let should_taint_output = self.is_operand_tainted(&alloca.num_elements);
                    if should_taint_output {
                        self.tainted_vars.insert(alloca.get_result());
                    }
                },
                Instruction::Load(load) => {
                    if self.is_operand_tainted(&load.address) {
                        panic!("Constant-time violation: load with tainted address {:?}", &load.address);
                    }
                    TODO;
                    // need more sophisticated type information here
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
