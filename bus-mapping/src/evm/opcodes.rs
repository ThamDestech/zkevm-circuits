//! Definition of each opcode of the EVM.
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::OpcodeId,
    operation::{
        AccountField, AccountOp, CallContextField, CallContextOp, TxAccessListAccountOp,
        TxReceiptField, TxReceiptOp, TxRefundOp, RW,
    },
    Error,
};
use core::fmt::Debug;
use eth_types::{
    evm_types::{GasCost, MAX_REFUND_QUOTIENT_OF_GAS_USED},
    GethExecStep, ToAddress, ToWord, Word,
};
use keccak256::EMPTY_HASH;
use log::warn;
use std::collections::HashMap;
use std::ops::Deref;

mod call;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callvalue;
mod chainid;
mod codecopy;
mod codesize;
mod dup;
mod extcodecopy;
mod extcodehash;
mod gasprice;
mod logs;
mod mload;
mod mstore;
mod number;
mod origin;
mod r#return;
mod returndatacopy;
mod selfbalance;
mod sload;
mod sstore;
mod stackonlyop;
mod stop;
mod swap;

use crate::evm::opcodes::extcodecopy::Extcodecopy;
use crate::evm::opcodes::r#return::Return;
use crate::evm::opcodes::returndatacopy::Returndatacopy;
use call::Call;
use calldatacopy::Calldatacopy;
use calldataload::Calldataload;
use calldatasize::Calldatasize;
use caller::Caller;
use callvalue::Callvalue;
use codecopy::Codecopy;
use codesize::Codesize;
use dup::Dup;
use eth_types::evm_types::Memory;
use extcodehash::Extcodehash;
use gasprice::GasPrice;
use logs::Log;
use mload::Mload;
use mstore::Mstore;
use origin::Origin;
use selfbalance::Selfbalance;
use sload::Sload;
use sstore::Sstore;
use stackonlyop::StackOnlyOpcode;
use stop::Stop;
use swap::Swap;

/// Generic opcode trait which defines the logic of the
/// [`Operation`](crate::operation::Operation) that should be generated for one
/// or multiple [`ExecStep`](crate::circuit_input_builder::ExecStep) depending
/// of the [`OpcodeId`] it contains.
pub trait Opcode: Debug {
    /// Generate the associated [`MemoryOp`](crate::operation::MemoryOp)s,
    /// [`StackOp`](crate::operation::StackOp)s, and
    /// [`StorageOp`](crate::operation::StorageOp)s associated to the Opcode
    /// is implemented for.
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error>;

    fn reconstruct_memory(
        &self,
        _state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Memory, Error> {
        Ok(geth_steps[0].memory.borrow().clone())
    }
}

#[derive(Debug, Copy, Clone)]
struct Dummy;

impl Opcode for Dummy {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        Ok(vec![state.new_step(&geth_steps[0])?])
    }
}

fn down_cast_to_opcode(opcode_id: &OpcodeId) -> Box<dyn Opcode> {
    if opcode_id.is_push() {
        return Box::new(StackOnlyOpcode::<0, 1>);
    }

    match opcode_id {
        OpcodeId::STOP => Box::new(Stop),
        OpcodeId::ADD => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::MUL => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SUB => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::DIV => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SDIV => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::MOD => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SMOD => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::ADDMOD => Box::new(StackOnlyOpcode::<3, 1>),
        OpcodeId::MULMOD => Box::new(StackOnlyOpcode::<3, 1>),
        OpcodeId::EXP => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SIGNEXTEND => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::LT => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::GT => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SLT => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SGT => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::EQ => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::ISZERO => Box::new(StackOnlyOpcode::<1, 1>),
        OpcodeId::AND => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::OR => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::XOR => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::NOT => Box::new(StackOnlyOpcode::<1, 1>),
        OpcodeId::BYTE => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SHL => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SHR => Box::new(StackOnlyOpcode::<2, 1>),
        OpcodeId::SAR => Box::new(StackOnlyOpcode::<2, 1>),
        // OpcodeId::SHA3 => Box::new({},
        // OpcodeId::ADDRESS => Box::new({},
        // OpcodeId::BALANCE => Box::new({},
        OpcodeId::ORIGIN => Box::new(Origin),
        OpcodeId::CALLER => Box::new(Caller),
        OpcodeId::CALLVALUE => Box::new(Callvalue),
        OpcodeId::CALLDATASIZE => Box::new(Calldatasize),
        OpcodeId::CALLDATALOAD => Box::new(Calldataload),
        OpcodeId::CALLDATACOPY => Box::new(Calldatacopy),
        OpcodeId::GASPRICE => Box::new(GasPrice),
        OpcodeId::CODECOPY => Box::new(Codecopy),
        OpcodeId::CODESIZE => Box::new(Codesize),
        // OpcodeId::EXTCODESIZE => Box::new({},
        OpcodeId::EXTCODECOPY => Box::new(Extcodecopy),
        // OpcodeId::RETURNDATASIZE => Box::new({},
        OpcodeId::RETURNDATACOPY => Box::new(Returndatacopy),
        OpcodeId::EXTCODEHASH => Box::new(Extcodehash),
        // OpcodeId::BLOCKHASH => Box::new({},
        OpcodeId::COINBASE => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::TIMESTAMP => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::NUMBER => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::DIFFICULTY => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::GASLIMIT => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::CHAINID => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::SELFBALANCE => Box::new(Selfbalance),
        OpcodeId::BASEFEE => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::POP => Box::new(StackOnlyOpcode::<1, 0>),
        OpcodeId::MLOAD => Box::new(Mload),
        OpcodeId::MSTORE => Box::new(Mstore::<false>),
        OpcodeId::MSTORE8 => Box::new(Mstore::<true>),
        OpcodeId::SLOAD => Box::new(Sload),
        OpcodeId::SSTORE => Box::new(Sstore),
        OpcodeId::JUMP => Box::new(StackOnlyOpcode::<1, 0>),
        OpcodeId::JUMPI => Box::new(StackOnlyOpcode::<2, 0>),
        OpcodeId::PC => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::MSIZE => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::GAS => Box::new(StackOnlyOpcode::<0, 1>),
        OpcodeId::JUMPDEST => Box::new(Dummy),
        OpcodeId::DUP1 => Box::new(Dup::<1>),
        OpcodeId::DUP2 => Box::new(Dup::<2>),
        OpcodeId::DUP3 => Box::new(Dup::<3>),
        OpcodeId::DUP4 => Box::new(Dup::<4>),
        OpcodeId::DUP5 => Box::new(Dup::<5>),
        OpcodeId::DUP6 => Box::new(Dup::<6>),
        OpcodeId::DUP7 => Box::new(Dup::<7>),
        OpcodeId::DUP8 => Box::new(Dup::<8>),
        OpcodeId::DUP9 => Box::new(Dup::<9>),
        OpcodeId::DUP10 => Box::new(Dup::<10>),
        OpcodeId::DUP11 => Box::new(Dup::<11>),
        OpcodeId::DUP12 => Box::new(Dup::<12>),
        OpcodeId::DUP13 => Box::new(Dup::<13>),
        OpcodeId::DUP14 => Box::new(Dup::<14>),
        OpcodeId::DUP15 => Box::new(Dup::<15>),
        OpcodeId::DUP16 => Box::new(Dup::<16>),
        OpcodeId::SWAP1 => Box::new(Swap::<1>),
        OpcodeId::SWAP2 => Box::new(Swap::<2>),
        OpcodeId::SWAP3 => Box::new(Swap::<3>),
        OpcodeId::SWAP4 => Box::new(Swap::<4>),
        OpcodeId::SWAP5 => Box::new(Swap::<5>),
        OpcodeId::SWAP6 => Box::new(Swap::<6>),
        OpcodeId::SWAP7 => Box::new(Swap::<7>),
        OpcodeId::SWAP8 => Box::new(Swap::<8>),
        OpcodeId::SWAP9 => Box::new(Swap::<9>),
        OpcodeId::SWAP10 => Box::new(Swap::<10>),
        OpcodeId::SWAP11 => Box::new(Swap::<11>),
        OpcodeId::SWAP12 => Box::new(Swap::<12>),
        OpcodeId::SWAP13 => Box::new(Swap::<13>),
        OpcodeId::SWAP14 => Box::new(Swap::<14>),
        OpcodeId::SWAP15 => Box::new(Swap::<15>),
        OpcodeId::SWAP16 => Box::new(Swap::<16>),
        OpcodeId::LOG0 => Box::new(Log),
        OpcodeId::LOG1 => Box::new(Log),
        OpcodeId::LOG2 => Box::new(Log),
        OpcodeId::LOG3 => Box::new(Log),
        OpcodeId::LOG4 => Box::new(Log),
        // OpcodeId::CREATE => {},
        OpcodeId::CALL => Box::new(Call),
        // OpcodeId::CALLCODE => {},
        OpcodeId::RETURN => Box::new(Return),
        // OpcodeId::DELEGATECALL => {},
        // OpcodeId::CREATE2 => {},
        // OpcodeId::STATICCALL => {},
        // REVERT is almost the same as RETURN
        OpcodeId::REVERT => Box::new(Return),
        OpcodeId::SELFDESTRUCT => {
            warn!("Using dummy gen_selfdestruct_ops for opcode SELFDESTRUCT");
            Box::new(DummySelfDestruct)
        }
        OpcodeId::CALLCODE | OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => {
            warn!("Using dummy gen_call_ops for opcode {:?}", opcode_id);
            Box::new(DummySelfDestruct)
        }
        OpcodeId::CREATE | OpcodeId::CREATE2 => {
            warn!("Using dummy gen_create_ops for opcode {:?}", opcode_id);
            Box::new(DummyCreate)
        }
        _ => {
            warn!("Using dummy gen_associated_ops for opcode {:?}", opcode_id);
            Box::new(Dummy)
        }
    }
}

/// Generate the associated operations according to the particular
/// [`OpcodeId`].
pub fn gen_associated_ops(
    opcode_id: &OpcodeId,
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let opcode = down_cast_to_opcode(opcode_id);
    if geth_steps.len() > 1 && opcode_id.need_reconstruction() {
        let memory = opcode.reconstruct_memory(state, geth_steps)?;
        if geth_steps[1].memory.borrow().is_empty() {
            geth_steps[1].memory.replace(memory.clone());
        } else {
            assert_eq!(&memory, geth_steps[1].memory.borrow().deref());
        }
        state.call_ctx_mut()?.memory = memory.0;
    }
    let result = opcode.gen_associated_ops(state, geth_steps);
    if result.is_ok()
        && geth_steps.len() > 1
        && !opcode_id.need_reconstruction()
        && geth_steps[1].memory.borrow().is_empty()
    {
        geth_steps[1]
            .memory
            .replace(geth_steps[0].memory.borrow().clone());
    }
    result
}

pub fn gen_begin_tx_ops(state: &mut CircuitInputStateRef) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_begin_tx_step();
    let call = state.call()?.clone();

    for (field, value) in [
        (CallContextField::TxId, state.tx_ctx.id().into()),
        (
            CallContextField::RwCounterEndOfReversion,
            call.rw_counter_end_of_reversion.into(),
        ),
        (
            CallContextField::IsPersistent,
            (call.is_persistent as usize).into(),
        ),
    ] {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: call.call_id,
                field,
                value,
            },
        );
    }

    // Increase caller's nonce
    let caller_address = call.caller_address;
    let nonce_prev = state.sdb.increase_nonce(&caller_address);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: caller_address,
            field: AccountField::Nonce,
            value: (nonce_prev + 1).into(),
            value_prev: nonce_prev.into(),
        },
    );

    // Add caller and callee into access list
    for address in [call.caller_address, call.address] {
        state.sdb.add_account_to_access_list(address);
        state.push_op(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: false,
            },
        );
    }

    // Calculate intrinsic gas cost
    let call_data_gas_cost = state
        .tx
        .input
        .iter()
        .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });
    let intrinsic_gas_cost = if state.tx.is_create() {
        GasCost::CREATION_TX.as_u64()
    } else {
        GasCost::TX.as_u64()
    } + call_data_gas_cost;
    exec_step.gas_cost = GasCost(intrinsic_gas_cost);

    // Transfer with fee
    state.transfer_with_fee(
        &mut exec_step,
        call.caller_address,
        call.address,
        call.value,
        state.tx.gas_price * state.tx.gas,
    )?;

    // Get code_hash of callee
    let (_, callee_account) = state.sdb.get_account(&call.address);
    let code_hash = callee_account.code_hash;

    // There are 4 branches from here.
    match (
        call.is_create(),
        state.is_precompiled(&call.address),
        code_hash.to_fixed_bytes() == *EMPTY_HASH,
    ) {
        // 1. Creation transaction.
        (true, _, _) => {
            warn!("Creation transaction is left unimplemented");
            Ok(exec_step)
        }
        // 2. Call to precompiled.
        (_, true, _) => {
            warn!("Call to precompiled is left unimplemented");
            Ok(exec_step)
        }
        (_, _, is_empty_code_hash) => {
            state.push_op(
                &mut exec_step,
                RW::READ,
                AccountOp {
                    address: call.address,
                    field: AccountField::CodeHash,
                    value: code_hash.to_word(),
                    value_prev: code_hash.to_word(),
                },
            );

            // 3. Call to account with empty code.
            if is_empty_code_hash {
                warn!("Call to account with empty code is left unimplemented");
                return Ok(exec_step);
            }

            // 4. Call to account with non-empty code.
            for (field, value) in [
                (CallContextField::Depth, call.depth.into()),
                (
                    CallContextField::CallerAddress,
                    call.caller_address.to_word(),
                ),
                (CallContextField::CalleeAddress, call.address.to_word()),
                (
                    CallContextField::CallDataOffset,
                    call.call_data_offset.into(),
                ),
                (
                    CallContextField::CallDataLength,
                    call.call_data_length.into(),
                ),
                (CallContextField::Value, call.value),
                (CallContextField::IsStatic, (call.is_static as usize).into()),
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
                (CallContextField::IsRoot, 1.into()),
                (CallContextField::IsCreate, 0.into()),
                (CallContextField::CodeSource, code_hash.to_word()),
            ] {
                state.push_op(
                    &mut exec_step,
                    RW::READ,
                    CallContextOp {
                        call_id: call.call_id,
                        field,
                        value,
                    },
                );
            }

            Ok(exec_step)
        }
    }
}

pub fn gen_end_tx_ops(
    state: &mut CircuitInputStateRef,
    cumulative_gas_used: &mut HashMap<usize, u64>,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_end_tx_step();
    let call = state.tx.calls()[0].clone();

    state.push_op(
        &mut exec_step,
        RW::READ,
        CallContextOp {
            call_id: call.call_id,
            field: CallContextField::TxId,
            value: state.tx_ctx.id().into(),
        },
    );
    state.push_op(
        &mut exec_step,
        RW::READ,
        CallContextOp {
            call_id: call.call_id,
            field: CallContextField::IsPersistent,
            value: Word::from(call.is_persistent as u8),
        },
    );

    let refund = state.sdb.refund();
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxRefundOp {
            tx_id: state.tx_ctx.id(),
            value: refund,
            value_prev: refund,
        },
    );

    let effective_refund =
        refund.min((state.tx.gas - exec_step.gas_left.0) / MAX_REFUND_QUOTIENT_OF_GAS_USED as u64);
    let (found, caller_account) = state.sdb.get_account_mut(&call.caller_address);
    if !found {
        return Err(Error::AccountNotFound(call.caller_address));
    }
    let caller_balance_prev = caller_account.balance;
    let caller_balance =
        caller_account.balance + state.tx.gas_price * (exec_step.gas_left.0 + effective_refund);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: call.caller_address,
            field: AccountField::Balance,
            value: caller_balance,
            value_prev: caller_balance_prev,
        },
    );

    let effective_tip = state.tx.gas_price - state.block.base_fee;
    let (found, coinbase_account) = state.sdb.get_account_mut(&state.block.coinbase);
    if !found {
        return Err(Error::AccountNotFound(state.block.coinbase));
    }
    let coinbase_balance_prev = coinbase_account.balance;
    let coinbase_balance =
        coinbase_account.balance + effective_tip * (state.tx.gas - exec_step.gas_left.0);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: state.block.coinbase,
            field: AccountField::Balance,
            value: coinbase_balance,
            value_prev: coinbase_balance_prev,
        },
    );

    // handle tx receipt tag
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxReceiptOp {
            tx_id: state.tx_ctx.id(),
            field: TxReceiptField::PostStateOrStatus,
            value: call.is_persistent as u64,
        },
    );

    let log_id = exec_step.log_id;
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxReceiptOp {
            tx_id: state.tx_ctx.id(),
            field: TxReceiptField::LogLength,
            value: log_id as u64,
        },
    );

    let gas_used = state.tx.gas - exec_step.gas_left.0;
    let mut current_cumulative_gas_used: u64 = 0;
    if state.tx_ctx.id() > 1 {
        current_cumulative_gas_used = *cumulative_gas_used.get(&(state.tx_ctx.id() - 1)).unwrap();
        // query pre tx cumulative gas
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxReceiptOp {
                tx_id: state.tx_ctx.id() - 1,
                field: TxReceiptField::CumulativeGasUsed,
                value: current_cumulative_gas_used,
            },
        );
    }

    state.push_op(
        &mut exec_step,
        RW::READ,
        TxReceiptOp {
            tx_id: state.tx_ctx.id(),
            field: TxReceiptField::CumulativeGasUsed,
            value: current_cumulative_gas_used + gas_used,
        },
    );

    cumulative_gas_used.insert(state.tx_ctx.id(), current_cumulative_gas_used + gas_used);

    if !state.tx_ctx.is_last_tx() {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.block_ctx.rwc.0 + 1,
                field: CallContextField::TxId,
                value: (state.tx_ctx.id() + 1).into(),
            },
        );
    }

    Ok(exec_step)
}

#[derive(Debug, Copy, Clone)]
struct DummyCall;

impl Opcode for DummyCall {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;

        let (_, account) = state.sdb.get_account(&call.address);
        let callee_code_hash = account.code_hash;

        let is_warm = state.sdb.check_account_in_access_list(&call.address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address: call.address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        state.push_call(call.clone(), geth_step);

        match (
            state.is_precompiled(&call.address),
            callee_code_hash.to_fixed_bytes() == *EMPTY_HASH,
        ) {
            // 1. Call to precompiled.
            (true, _) => Ok(vec![exec_step]),
            // 2. Call to account with empty code.
            (_, true) => {
                state.handle_return(geth_step)?;
                Ok(vec![exec_step])
            }
            // 3. Call to account with non-empty code.
            (_, false) => Ok(vec![exec_step]),
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct DummyCreate;

impl Opcode for DummyCreate {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;

        // Increase caller's nonce
        let nonce_prev = state.sdb.get_nonce(&call.caller_address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            AccountOp {
                address: call.caller_address,
                field: AccountField::Nonce,
                value: (nonce_prev + 1).into(),
                value_prev: nonce_prev.into(),
            },
        )?;

        // Add callee into access list
        let is_warm = state.sdb.check_account_in_access_list(&call.address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address: call.address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        state.push_call(call.clone(), geth_step);

        // Increase callee's nonce
        let nonce_prev = state.sdb.get_nonce(&call.address);
        debug_assert!(nonce_prev == 0);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            AccountOp {
                address: call.address,
                field: AccountField::Nonce,
                value: 1.into(),
                value_prev: 0.into(),
            },
        )?;

        state.transfer(
            &mut exec_step,
            call.caller_address,
            call.address,
            call.value,
        )?;

        if call.code_hash.to_fixed_bytes() == *EMPTY_HASH {
            // 1. Create with empty initcode.
            state.handle_return(geth_step)?;
            Ok(vec![exec_step])
        } else {
            // 2. Create with non-empty initcode.
            Ok(vec![exec_step])
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct DummySelfDestruct;

impl Opcode for DummySelfDestruct {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let sender = state.call()?.address;
        let receiver = geth_step.stack.last()?.to_address();

        let is_warm = state.sdb.check_account_in_access_list(&receiver);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address: receiver,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        let (found, receiver_account) = state.sdb.get_account(&receiver);
        if !found {
            return Err(Error::AccountNotFound(receiver));
        }
        let value = receiver_account.balance;
        state.transfer(&mut exec_step, sender, receiver, value)?;

        if state.call()?.is_persistent {
            state.sdb.destruct_account(sender);
        }

        Ok(vec![exec_step])
    }
}
