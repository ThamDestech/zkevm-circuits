//! Execution step related module.

use crate::{error::ExecError, exec_trace::OperationRef, operation::RWCounter};
use eth_types::{
    evm_types::{Gas, GasCost, OpcodeId, ProgramCounter},
    GethExecStep, U256,
};

/// An execution step of the EVM.
#[derive(Clone, Debug)]
pub struct ExecStep {
    /// Execution state
    pub exec_state: ExecState,
    /// Program Counter
    pub pc: ProgramCounter,
    /// Stack size
    pub stack_size: usize,
    /// Memory size
    pub memory_size: usize,
    /// Gas left
    pub gas_left: Gas,
    /// Gas cost of the step.  If the error is OutOfGas caused by a "gas uint64
    /// overflow", this value will **not** be the actual Gas cost of the
    /// step.
    pub gas_cost: GasCost,
    /// Accumulated gas refund
    pub gas_refund: Gas,
    /// Call index within the Transaction.
    pub call_index: usize,
    /// The global counter when this step was executed.
    pub rwc: RWCounter,
    /// Reversible Write Counter.  Counter of write operations in the call that
    /// will need to be undone in case of a revert.
    pub reversible_write_counter: usize,
    /// Log index when this step was executed.
    pub log_id: usize,
    /// The list of references to Operations in the container
    pub bus_mapping_instance: Vec<OperationRef>,
    /// Error generated by this step
    pub error: Option<ExecError>,
    /// Step auxiliary data
    pub aux_data: Option<StepAuxiliaryData>,
}

impl ExecStep {
    /// Create a new Self from a `GethExecStep`.
    pub fn new(
        step: &GethExecStep,
        call_index: usize,
        rwc: RWCounter,
        reversible_write_counter: usize,
        log_id: usize,
    ) -> Self {
        ExecStep {
            exec_state: ExecState::Op(step.op),
            pc: step.pc,
            stack_size: step.stack.0.len(),
            memory_size: step.memory.borrow().len(),
            gas_left: step.gas,
            gas_cost: step.gas_cost,
            gas_refund: Gas(0),
            call_index,
            rwc,
            reversible_write_counter,
            log_id,
            bus_mapping_instance: Vec::new(),
            error: None,
            aux_data: None,
        }
    }
}

impl Default for ExecStep {
    fn default() -> Self {
        Self {
            exec_state: ExecState::Op(OpcodeId::INVALID(0)),
            pc: ProgramCounter(0),
            stack_size: 0,
            memory_size: 0,
            gas_left: Gas(0),
            gas_cost: GasCost(0),
            gas_refund: Gas(0),
            call_index: 0,
            rwc: RWCounter(0),
            reversible_write_counter: 0,
            log_id: 0,
            bus_mapping_instance: Vec::new(),
            error: None,
            aux_data: None,
        }
    }
}

/// Execution state
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecState {
    /// EVM Opcode ID
    Op(OpcodeId),
    /// Virtual step Begin Tx
    BeginTx,
    /// Virtual step End Tx
    EndTx,
    /// Virtual step Copy To Memory
    CopyToMemory,
    /// Virtual step Copy To Log
    CopyToLog,
    /// Virtal step Copy Code To Memory
    CopyCodeToMemory,
}

impl ExecState {
    /// Returns `true` if `ExecState` is an opcode and the opcode is a `PUSHn`.
    pub fn is_push(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_push()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_dup()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_swap()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `Logn`.
    pub fn is_log(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_log()
        } else {
            false
        }
    }
}

/// Provides specific details about the data copy for which an
/// [`StepAuxiliaryData`] holds info about.
#[derive(Clone, Copy, Debug)]
pub enum CopyDetails {
    /// Origin of the copied bytes is or not the Tx CallData.
    TxCallData(bool),
    /// Origin of the copied bytes is bytecode. For which it's hash is provided.
    Code(U256),
    /// The bytes are being copied to a Log.
    /// Call's state change's persistance and tx_id are provided.
    /// the data start index when enter this copy step
    Log((bool, usize, usize)),
}

/// Auxiliary data of Execution step
#[derive(Clone, Copy, Debug)]
pub struct StepAuxiliaryData {
    /// Source start address
    pub(crate) src_addr: u64,
    /// Destination address. (0x00..00 for Log related aux data).
    pub(crate) dst_addr: u64,
    /// Bytes left
    pub(crate) bytes_left: u64,
    /// Source end address
    pub(crate) src_addr_end: u64,
    /// Detail info about the copied data.
    pub(crate) copy_details: CopyDetails,
}

impl StepAuxiliaryData {
    /// Generates a new `StepAuxiliaryData` instance.
    pub fn new(
        src_addr: u64,
        dst_addr: u64,
        bytes_left: u64,
        src_addr_end: u64,
        copy_details: CopyDetails,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            copy_details,
        }
    }

    /// Source start address
    pub fn src_addr(&self) -> u64 {
        self.src_addr
    }

    /// Destination address
    pub fn dst_addr(&self) -> u64 {
        self.dst_addr
    }

    /// Bytes left
    pub fn bytes_left(&self) -> u64 {
        self.bytes_left
    }

    /// Source end address
    pub fn src_addr_end(&self) -> u64 {
        self.src_addr_end
    }

    /// Indicate origin of the data to copy
    pub fn copy_details(&self) -> CopyDetails {
        self.copy_details
    }

    /// Returns true if the data origin is Code.
    pub fn is_code_originated(&self) -> bool {
        matches!(self.copy_details, CopyDetails::Code(_))
    }

    /// Returns true if the data origin is a Tx.
    pub fn is_tx_originated(&self) -> bool {
        matches!(self.copy_details, CopyDetails::TxCallData(_))
    }

    /// Returns true if the data is copied to Logs.
    pub fn is_log_destinated(&self) -> bool {
        matches!(self.copy_details, CopyDetails::Log(_))
    }
}
