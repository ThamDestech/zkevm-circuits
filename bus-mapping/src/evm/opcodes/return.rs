use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::Error;
use eth_types::{Address, GethExecStep, ToAddress, ToBigEndian};
use eth_types::evm_types::Memory;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;

impl Opcode for Return {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_call = state.call()?.clone();

        let geth_step = &geth_steps[0];
        let offset = geth_step.stack.nth_last(0)?.as_usize();
        let length = geth_step.stack.nth_last(1)?.as_usize();

        if !current_call.is_create() {
            // copy return data
            let (_, caller_idx) = state
                .block_ctx
                .call_map
                .get(&current_call.caller_id)
                .expect("caller id not found in call map");
            let caller_ctx = &mut state.tx_ctx.calls[*caller_idx];
            // update to the caller memory
            let return_offset = current_call.return_data_offset as usize;
            caller_ctx.memory.resize(return_offset + length, 0);
            caller_ctx.memory[return_offset..return_offset + length]
                .copy_from_slice(&geth_steps[0].memory.borrow().0[offset..offset + length]);
            caller_ctx.return_data.resize(length as usize, 0);
            caller_ctx
                .return_data
                .copy_from_slice(&geth_steps[0].memory.borrow().0[offset..offset + length]);
            caller_ctx.last_call = Some(current_call);
            if geth_steps[1].memory.borrow().is_empty() {
                geth_steps[1].memory.replace(Memory::from(caller_ctx.memory.clone()));
            } else {
                assert_eq!(&caller_ctx.memory, &geth_steps[1].memory.borrow().0);
            }
        } else {
            // dealing with contract creation
            assert!(offset + length <= geth_step.memory.borrow().0.len());
            let code = geth_step.memory.borrow().0[offset..offset + length].to_vec();
            let contract_addr = geth_steps[1].stack.nth_last(0)?.to_address();
            state.code_db.insert(Some(contract_addr), code);
        }

        // let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];
        // let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        // exec_steps.extend(memory_copy_steps);
        // Ok(exec_steps)
        let exec_step = state.new_step(&geth_steps[0])?;
        state.handle_return(&geth_steps[0])?;
        Ok(vec![exec_step])
    }
}

// TODO: circuit implement
// fn gen_calldatacopy_step(
//     state: &mut CircuitInputStateRef,
//     geth_step: &GethExecStep,
// ) -> Result<ExecStep, Error> {
//     let mut exec_step = state.new_step(geth_step)?;
//
//     let memory_offset = geth_step.stack.nth_last(0)?;
//     let memory_size = geth_step.stack.nth_last(1)?;
//
//     if cfg!(debug_assertions) {
//         let current_call = state.call()?;
//         debug_assert_eq!(memory_offset.as_u64(),
// current_call.return_data_offset);         debug_assert_eq!(memory_size.
// as_u64(), current_call.return_data_length);     }
//
//     state.push_stack_op(
//         &mut exec_step,
//         RW::READ,
//         geth_step.stack.nth_last_filled(0),
//         memory_offset,
//     )?;
//     state.push_stack_op(
//         &mut exec_step,
//         RW::READ,
//         geth_step.stack.nth_last_filled(1),
//         memory_size,
//     )?;
//
//     Ok(exec_step)
// }
//
// fn gen_memory_copy_steps(
//     state: &mut CircuitInputStateRef,
//     geth_steps: &[GethExecStep],
// ) -> Result<Vec<ExecStep>, Error> {
//
//     let memory_offset = geth_steps[0].stack.nth_last(0)?;
//     let memory_size = geth_steps[0].stack.nth_last(1)?;
//
//     if current_call.is_success && !current_call.is_create() {
//         let length = current_call.return_data_length;
//         let offset = current_call.return_data_offset;
//
//         // update to the caller memory
//         debug_assert_eq!(caller.return_data_length, length);
//         let return_offset = caller.return_data_offset;
//         caller_ctx.memory[return_offset..return_offset +
// length].copy_from_slice(step.memory[offset..offset + length]);     }
//
//     Ok(vec![])
// }

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_ok() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL
            STOP
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_revert() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // REVERT
        //
        // bytecode: 0x6020600060003760206000FD
        //
        // // constructor
        // PUSH12 0x6020600060003760206000FD
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000FD600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000FD600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL
            STOP
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
