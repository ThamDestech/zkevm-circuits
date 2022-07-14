use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::opcodes::stackonlyop::StackOnlyOpcode;
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::Memory;
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Sha3;

impl Opcode for Sha3 {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // TODO: memory reads
        log::warn!("incomplete SHA3 implementation");
        StackOnlyOpcode::<2, 1>.gen_associated_ops(state, geth_steps)
    }

    fn reconstruct_memory(
        &self,
        _state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Memory, Error> {
        let geth_step = &geth_steps[0];
        let offset = geth_step.stack.nth_last(0)?.as_usize();
        let length = geth_step.stack.nth_last(1)?.as_usize();

        let mut memory = geth_step.memory.borrow().clone();
        memory.extend_at_least(offset + length);

        Ok(memory)
    }
}
