use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDetails, ExecState, ExecStep, StepAuxiliaryData,
    },
    constants::MAX_COPY_BYTES,
    Error,
};
use eth_types::evm_types::Memory;
use eth_types::{GethExecStep, ToWord};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codecopy;

impl Opcode for Codecopy {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_codecopy_step(state, geth_step)?];
        let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        exec_steps.extend(memory_copy_steps);
        Ok(exec_steps)
    }

    fn reconstruct_memory(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Memory, Error> {
        let dest_offset = geth_steps[0].stack.nth_last(0)?.as_u64();
        let code_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
        let length = geth_steps[0].stack.nth_last(2)?.as_u64();

        let code_hash = state.call()?.code_hash;
        let code = state.code(code_hash)?;

        let mut memory = geth_steps[0].memory.replace(Memory::default());
        if length != 0 {
            let minimal_length = (dest_offset + length) as usize;
            memory.extend_at_least(minimal_length);

            let mem_starts = dest_offset as usize;
            let mem_ends = mem_starts + length as usize;
            let code_starts = code_offset as usize;
            let code_ends = code_starts + length as usize;
            if code_ends <= code.len() {
                memory[mem_starts..mem_ends].copy_from_slice(&code[code_starts..code_ends]);
            } else if let Some(actual_length) = code.len().checked_sub(code_starts) {
                let mem_code_ends = mem_starts + actual_length;
                memory[mem_starts..mem_code_ends].copy_from_slice(&code[code_starts..]);
                // since we already resize the memory, no need to copy 0s for
                // out of bound bytes
            }
        }
        Ok(memory)
    }
}

fn gen_codecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let dest_offset = geth_step.stack.nth_last(0)?;
    let code_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    // stack reads
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(0),
        dest_offset,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        code_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

    Ok(exec_step)
}

fn gen_memory_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    aux_data: StepAuxiliaryData,
    code: &[u8],
) -> Result<(), Error> {
    for idx in 0..std::cmp::min(aux_data.bytes_left as usize, MAX_COPY_BYTES) {
        let addr = (aux_data.src_addr as usize) + idx;
        let byte = if addr < (aux_data.src_addr_end as usize) {
            code[addr]
        } else {
            0
        };
        state.memory_write(exec_step, ((aux_data.dst_addr as usize) + idx).into(), byte)?;
    }

    exec_step.aux_data = Some(aux_data);

    Ok(())
}

fn gen_memory_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let dest_offset = geth_steps[0].stack.nth_last(0)?.as_u64();
    let code_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
    let length = geth_steps[0].stack.nth_last(2)?.as_u64();

    let code_hash = state.call()?.code_hash;
    let code = state.code(code_hash)?;
    let src_addr_end = code.len() as u64;

    let code_hash = code_hash.to_word();
    let mut copied = 0;
    let mut steps = vec![];
    while copied < length {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.exec_state = ExecState::CopyCodeToMemory;
        gen_memory_copy_step(
            state,
            &mut exec_step,
            StepAuxiliaryData::new(
                code_offset + copied,
                dest_offset + copied,
                length - copied,
                src_addr_end,
                CopyDetails::Code(code_hash),
            ),
            &code,
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES as u64;
    }

    Ok(steps)
}

#[cfg(test)]
mod codecopy_tests {
    use eth_types::{
        bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{
        test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        TestContext,
    };

    use crate::{
        mock::BlockData,
        operation::{MemoryOp, StackOp, RW},
    };

    use super::*;

    #[test]
    fn codecopy_opcode_impl() {
        test_ok(0x00, 0x00, 0x40);
        test_ok(0x20, 0x40, 0xA0);
    }

    fn test_ok(dest_offset: usize, code_offset: usize, size: usize) {
        let code = bytecode! {
            PUSH32(size)
            PUSH32(code_offset)
            PUSH32(dest_offset)
            CODECOPY
            STOP
        };

        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code.clone()),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODECOPY))
            .unwrap();

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1021), Word::from(dest_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(code_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(size)),
                ),
            ]
        );
        assert_eq!(
            (0..size)
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            (0..size)
                .map(|idx| {
                    (
                        RW::WRITE,
                        MemoryOp::new(
                            1,
                            MemoryAddress::from(dest_offset + idx),
                            if code_offset + idx < code.code().len() {
                                code.code()[code_offset + idx]
                            } else {
                                0
                            },
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryOp)>>(),
        );
    }
}
