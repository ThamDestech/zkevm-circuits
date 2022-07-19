use ethers_core::types::U256;
use eth_types::evm_types::Memory;
use eth_types::{Address, U512};

pub fn execute_precompiled(address: &Address, input: &[u8]) -> Memory {
    (match address.as_bytes()[19] {
        0x01 => ec_recover,
        0x02 => sha2_256,
        0x03 => ripemd_160,
        0x04 => identity,
        0x05 => modexp,
        0x06 => ec_add,
        0x07 => ec_mul,
        0x08 => ec_pairing,
        _ => panic!("calling non-exist precompiled contract address"),
    })(input)
}

macro_rules! at_least_length {
    ($target: ident, $length: expr) => {
        {
            let _length = $length;
            if $target.len() < _length {
                return ::eth_types::evm_types::Memory::new()
            }
        }
    }
}

fn ec_recover(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn sha2_256(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ripemd_160(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn identity(input: &[u8]) -> Memory {
    Memory::from(input.to_vec())
}

fn modexp(input: &[u8]) -> Memory {
    at_least_length!(input, 96);
    let b_size = U256::from_big_endian(&input[0..32]).as_usize();
    let e_size = U256::from_big_endian(&input[32..64]).as_usize();
    let m_size = U256::from_big_endian(&input[64..96]).as_usize();
    at_least_length!(input, 96 + b_size + e_size + m_size);
    let b = U512::from_big_endian(&input[96..96 + b_size]);
    let e = U512::from_big_endian(&input[96 + b_size..96 + b_size + e_size]);
    let m = U512::from_big_endian(&input[96 + b_size + e_size..96 + b_size + e_size + m_size]);

    let c = mod_exp_inner(b, e, m);
    let mut buf = Vec::new();
    buf.resize(64, 0);
    c.to_big_endian(&mut buf);

    let mut mem = Memory::new();
    mem.extend_at_least(m_size);
    mem.0[..m_size].copy_from_slice(&buf[64 - m_size..]);
    mem
}

fn mod_exp_inner(b: U512, e: U512, m: U512) -> U512 {
    if m == U512::one() {
        return U512::zero();
    }
    let mut c = U512::one();
    let mut _e = U512::zero();
    while _e < e {
        c = (c * b) % m;
        _e += U512::one();
    }
    c
}

fn ec_add(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ec_mul(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ec_pairing(_input: &[u8]) -> Memory {
    unimplemented!()
}

#[cfg(test)]
mod precompiled_tests {
    use eth_types::{bytecode, word};
    use eth_types::geth_types::GethData;
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;
    use crate::mock::BlockData;

    #[test]
    fn test_modexp() {
        let code = bytecode! {
            PUSH1(1)
            PUSH1(0)
            MSTORE
            PUSH1(1)
            PUSH1(0x20)
            MSTORE
            PUSH1(1)
            PUSH1(0x40)
            MSTORE
            PUSH32(word!("08090A0000000000000000000000000000000000000000000000000000000000"))
            PUSH1(0x60)
            MSTORE

            // Do the call
            PUSH1(1) // retSize
            PUSH1(0x9F) // retOffset
            PUSH1(0x63) // argsSize
            PUSH1(0) // argsOffset
            PUSH1(5) // address
            PUSH1(0xFF) // gas
            STATICCALL
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