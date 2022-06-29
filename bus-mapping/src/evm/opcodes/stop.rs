use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use eth_types::evm_types::Memory;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::STOP`](crate::evm::OpcodeId::STOP)
/// `OpcodeId`. This is responsible of generating all of the associated
/// operations and place them inside the trace's
/// [`OperationContainer`](crate::operation::OperationContainer). In the case of
/// STOP, it simply does not add anything.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Stop;

impl Opcode for Stop {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let exec_step = state.new_step(geth_step)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }

    fn reconstruct_memory(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Memory, Error> {
        let current_call = state.call()?.clone();
        if !current_call.is_root {
            let caller_ctx = state.caller_ctx_mut()?;
            let length = current_call.return_data_offset + current_call.return_data_length;
            caller_ctx.memory.extend_at_least(length as usize);
            Ok(caller_ctx.memory.clone())
        } else {
            Ok(geth_steps[0].memory.borrow().clone())
        }
    }
}
