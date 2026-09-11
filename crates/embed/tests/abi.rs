//! The core ABI, pinned over a byte-vector memory.
//!
//! Both engines run this dispatch, so no differential lane can catch it
//! drifting; what a lane would see is two engines agreeing on a wrong
//! encoding. This is the pin: every register rule, every fixed-width
//! encoding, and every refusal the boundary makes, asserted against a
//! host that records what reached it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use hyperscale_vm_embed::abi::{
    self, AMOUNT_BYTES, Boundary, CoreType, CoreValue, DRAWN_EXPIRED, DRAWN_PENDING, DRAWN_READY,
    GuestMemory, IMPORTS, LIMBS_BYTES, ORDERING_GREATER, ORDERING_LESS, ParamKind, ROUNDING_DOWN,
    ROUNDING_UP, Registers, Reply,
};
use hyperscale_vm_embed::meter::{Exhausted, FuelSink, HostAccess, MeterError};
use hyperscale_vm_embed::{GuestArg, KernelHost};
use hyperscale_vm_types::math::U256;
use hyperscale_vm_types::{AbortReason, Address, Drawn, PrincipalAddr};

const AMOUNT: u128 = 0x0123_4567_89AB_CDEF_1122_3344_5566_7788;
const WIDE: U256 = U256::from_limbs([1, 2, 3, 4]);
const WORD: [u8; 32] = [0xA5; 32];

type Calls = Arc<Mutex<Vec<String>>>;

/// A host that records every call with its arguments and answers
/// values wide enough to show a wrong half.
struct Recorder {
    calls: Calls,
    drawn: Drawn,
    refuse: bool,
}

impl Recorder {
    fn op<T>(&self, call: String, value: T) -> Result<T, AbortReason> {
        self.calls.lock().unwrap().push(call);
        if self.refuse {
            Err(AbortReason::CellUnderflow)
        } else {
            Ok(value)
        }
    }
}

impl KernelHost for Recorder {
    fn site_len(&mut self, site: u32) -> Result<u32, AbortReason> {
        self.op(format!("site-len({site})"), 4)
    }
    fn site_declared(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        self.op(format!("site-declared({site},{element})"), true)
    }
    fn site_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, AbortReason> {
        self.op(format!("site-get({site},{element})"), b"cell".to_vec())
    }
    fn site_set(&mut self, site: u32, element: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        self.op(format!("site-set({site},{element},{value:?})"), ())
    }
    fn site_clear(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        self.op(format!("site-clear({site},{element})"), ())
    }
    fn site_balance(&mut self, site: u32, element: u32) -> Result<u128, AbortReason> {
        self.op(format!("site-balance({site},{element})"), AMOUNT)
    }
    fn burn(&mut self, funds: u32) -> Result<(), AbortReason> {
        self.op(format!("burn({funds})"), ())
    }
    fn mint(&mut self, grant: u32, amount: u128) -> Result<u32, AbortReason> {
        self.op(format!("mint({grant},{amount:#x})"), 11)
    }
    fn mint_instances(&mut self, grant: u32, ids: &[u64]) -> Result<u32, AbortReason> {
        self.op(format!("mint-instances({grant},{ids:?})"), 12)
    }
    fn site_instance_take(
        &mut self,
        site: u32,
        element: u32,
        ids: &[u64],
    ) -> Result<u32, AbortReason> {
        self.op(format!("site-instance-take({site},{element},{ids:?})"), 13)
    }
    fn site_instance_put(
        &mut self,
        site: u32,
        element: u32,
        funds: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op(
            format!("site-instance-put({site},{element},{funds},{value:?})"),
            (),
        )
    }
    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        self.op(format!("bucket-take({rep},{amount:#x})"), 14)
    }
    fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, AbortReason> {
        self.op(
            format!("bucket-split({rep},{:?},{:?})", num.limbs(), den.limbs()),
            15,
        )
    }
    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason> {
        self.op(format!("bucket-put({rep},{other})"), ())
    }
    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason> {
        self.op(format!("bucket-amount({rep})"), AMOUNT)
    }
    fn site_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), AbortReason> {
        self.op(format!("site-put({site},{element},{funds})"), ())
    }
    fn site_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, AbortReason> {
        self.op(format!("site-take({site},{element},{amount:#x})"), 16)
    }
    fn site_reserve_take(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        self.op(format!("site-reserve-take({site},{element})"), 17)
    }
    fn take_scan_debt(&mut self) -> usize {
        0
    }
    fn scan_floor(&mut self, _site: u32, _element: u32) -> Result<usize, AbortReason> {
        Ok(0)
    }
    fn site_count(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        self.op(format!("site-count({site},{element})"), 3)
    }
    fn site_covered(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        self.op(format!("site-covered({site},{element})"), false)
    }
    fn site_order(&mut self, site: u32, element: u32, index: u32) -> Result<u128, AbortReason> {
        self.op(format!("site-order({site},{element},{index})"), AMOUNT)
    }
    fn site_entry(&mut self, site: u32, element: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
        self.op(format!("site-entry({site},{element},{index})"), vec![])
    }
    fn site_entry_set(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op(
            format!("site-entry-set({site},{element},{index},{value:?})"),
            (),
        )
    }
    fn site_insert(
        &mut self,
        site: u32,
        element: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op(
            format!("site-insert({site},{element},{order:#x},{value:?})"),
            (),
        )
    }
    fn site_remove(&mut self, site: u32, element: u32, index: u32) -> Result<(), AbortReason> {
        self.op(format!("site-remove({site},{element},{index})"), ())
    }
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
        self.op(format!("bucket-drop({rep})"), ())
    }
    fn clock_ms(&self) -> u64 {
        0xDEAD_BEEF_0000_0001
    }
    fn site_seal(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        self.op(format!("site-seal({site},{element})"), ())
    }
    fn site_open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, AbortReason> {
        self.op(format!("site-open-seal({site},{element})"), self.drawn)
    }
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        self.calls.lock().unwrap().push(format!("hash({data:?})"));
        [u8::try_from(data.len()).unwrap_or(u8::MAX); 32]
    }
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason> {
        self.op(format!("emit({event_type},{payload:?})"), ())
    }
}

/// The boundary over a recording host, unbounded fuel, and the registers
/// `lower` built.
struct Port {
    host: Recorder,
    calls: Calls,
    registers: Registers,
    mem: Vec<u8>,
    spent: u64,
}

impl Port {
    fn new(args: &[GuestArg<'_>]) -> (Self, Vec<CoreValue>) {
        let calls = Calls::default();
        let (values, registers) = abi::lower(args).expect("bounded");
        let port = Self {
            host: Recorder {
                calls: Arc::clone(&calls),
                drawn: Drawn::Ready(WORD),
                refuse: false,
            },
            calls,
            registers,
            mem: vec![0; 256],
            spent: 0,
        };
        (port, values)
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl HostAccess for Port {
    type Host = Recorder;
    fn host(&mut self) -> &mut Recorder {
        &mut self.host
    }
}

impl FuelSink for Port {
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted> {
        self.spent += fuel;
        Ok(())
    }
}

impl GuestMemory for Port {
    fn read(&self, ptr: u32, len: u32) -> Result<&[u8], MeterError> {
        self.mem.as_slice().read(ptr, len)
    }
    fn write(&mut self, ptr: u32, bytes: &[u8]) -> Result<(), MeterError> {
        self.mem.as_mut_slice().write(ptr, bytes)
    }
}

impl Boundary for Port {
    fn registers(&mut self) -> &mut Registers {
        &mut self.registers
    }
}

const VIOLATION: MeterError = MeterError::Refused(AbortReason::AbiViolation);
const BAD_SHAPE: MeterError = MeterError::Refused(AbortReason::BadReturnShape);

/// Sixteen bytes, low half first: what a little-endian `u128` is, and
/// what the ABI states an amount as.
fn amount_bytes(amount: u128) -> [u8; AMOUNT_BYTES] {
    let mut bytes = [0u8; AMOUNT_BYTES];
    bytes[..8].copy_from_slice(
        &u64::try_from(amount & u128::from(u64::MAX))
            .unwrap()
            .to_le_bytes(),
    );
    bytes[8..].copy_from_slice(&u64::try_from(amount >> 64).unwrap().to_le_bytes());
    bytes
}

fn limb_bytes(wide: U256) -> [u8; LIMBS_BYTES] {
    let mut bytes = [0u8; LIMBS_BYTES];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(wide.limbs()) {
        *chunk = limb.to_le_bytes();
    }
    bytes
}

const fn address() -> Address {
    PrincipalAddr::new([0x42; 31]).address()
}

// ---- the export convention -----------------------------------------------

/// Scalars flatten in place; every register argument flattens to its
/// byte length and fills the register at its own position.
#[test]
fn lower_flattens_scalars_and_fills_registers_by_position() {
    let args = [
        GuestArg::Site { site: 3 },
        GuestArg::Bool(true),
        GuestArg::U64(u64::MAX - 1),
        GuestArg::Address(address()),
        GuestArg::Bytes(b"hello"),
        GuestArg::Ids(&[1, 0x0100_0000_0000_0002]),
        GuestArg::Bucket(9),
    ];
    let (mut port, values) = Port::new(&args);
    assert_eq!(
        values,
        vec![
            CoreValue::I32(3),
            CoreValue::I32(1),
            CoreValue::I64(u64::MAX - 1),
            CoreValue::I32(32),
            CoreValue::I32(5),
            CoreValue::I32(16),
            CoreValue::I32(9),
        ]
    );
    abi::arg(&mut port, 3, 0).expect("the address register");
    assert_eq!(&port.mem[..32], &address().to_bytes());
    abi::arg(&mut port, 4, 40).expect("the bytes register");
    assert_eq!(&port.mem[40..45], b"hello");
    abi::arg(&mut port, 5, 64).expect("the ids register");
    assert_eq!(&port.mem[64..72], &1u64.to_le_bytes());
    assert_eq!(&port.mem[72..80], &0x0100_0000_0000_0002u64.to_le_bytes());
    // Nothing else is a register: a scalar's position, one past the
    // end, and a register already collected all refuse alike.
    for index in [0, 1, 2, 6, 7, u32::MAX, 3, 4, 5] {
        assert_eq!(
            abi::arg(&mut port, index, 0),
            Err(VIOLATION),
            "register {index}"
        );
    }
}

/// The kind table is the whole of what a core signature says.
#[test]
fn every_kind_flattens_to_the_type_the_table_states() {
    assert_eq!(ParamKind::Site.core_type(), CoreType::I32);
    assert_eq!(ParamKind::Flag.core_type(), CoreType::I32);
    assert_eq!(ParamKind::U64.core_type(), CoreType::I64);
    assert_eq!(ParamKind::Address.core_type(), CoreType::I32);
    assert_eq!(ParamKind::Bytes.core_type(), CoreType::I32);
    assert_eq!(ParamKind::Ids.core_type(), CoreType::I32);
    assert_eq!(ParamKind::Bucket.core_type(), CoreType::I32);
    assert_eq!(GuestArg::Ids(&[]).kind(), ParamKind::Ids);
    assert_eq!(GuestArg::Bool(false).kind(), ParamKind::Flag);
    assert_eq!(abi::returns(false), &[]);
    assert_eq!(abi::returns(true), &[CoreType::I32]);
}

/// A reply is exactly once; an answer at most once; and what comes
/// back is what was written, in order.
#[test]
fn reply_and_answer_read_back_once_each() {
    let (mut port, _) = Port::new(&[]);
    assert_eq!(port.registers().reply(), None, "no reply yet");

    port.mem[0..4].copy_from_slice(&7u32.to_le_bytes());
    port.mem[4..8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    port.mem[8..11].copy_from_slice(b"yes");
    abi::answer(&mut port, 8, 3).expect("an answer");
    assert_eq!(abi::answer(&mut port, 8, 3), Err(BAD_SHAPE));
    abi::reply(&mut port, 0, 2).expect("a reply");
    assert_eq!(abi::reply(&mut port, 0, 0), Err(BAD_SHAPE));

    assert_eq!(
        port.registers().reply(),
        Some(Reply {
            edges: vec![7, 0xFFFF_FFF0],
            answer: Some(b"yes".to_vec()),
        })
    );
    assert_eq!(port.registers().reply(), None, "read back once");
}

/// An export that answers nothing replies with edges alone, and a
/// zero-length answer is an answer.
#[test]
fn an_empty_answer_is_distinct_from_none() {
    let (mut port, _) = Port::new(&[]);
    abi::reply(&mut port, 0, 0).expect("a reply");
    assert_eq!(
        port.registers().reply(),
        Some(Reply {
            edges: vec![],
            answer: None
        })
    );

    let (mut port, _) = Port::new(&[]);
    abi::answer(&mut port, 0, 0).expect("an empty answer");
    abi::reply(&mut port, 0, 0).expect("a reply");
    assert_eq!(
        port.registers().reply(),
        Some(Reply {
            edges: vec![],
            answer: Some(vec![])
        })
    );
}

// ---- the answer register -------------------------------------------------

/// A variable-length result returns its length and waits in the answer
/// register until the one take collects it.
#[test]
fn a_variable_length_result_waits_in_the_answer_register() {
    let (mut port, _) = Port::new(&[]);
    assert_eq!(abi::take(&mut port, 0), Err(VIOLATION));

    assert_eq!(abi::site_get(&mut port, 1, 2), Ok(4));
    abi::take(&mut port, 10).expect("the register");
    assert_eq!(&port.mem[10..14], b"cell");
    assert_eq!(abi::take(&mut port, 10), Err(VIOLATION));
    assert_eq!(port.calls(), ["site-get(1,2)"]);
}

/// Zero bytes fill the register the same as any other length.
#[test]
fn a_zero_length_result_fills_the_register() {
    let (mut port, _) = Port::new(&[]);
    assert_eq!(abi::site_entry(&mut port, 1, 2, 3), Ok(0));
    abi::take(&mut port, 0).expect("an empty register collects");
    assert_eq!(abi::take(&mut port, 0), Err(VIOLATION));
}

/// A result nobody took was paid for; the next one replaces it.
#[test]
fn an_uncollected_result_is_replaced_by_the_next() {
    let (mut port, _) = Port::new(&[]);
    assert_eq!(abi::site_get(&mut port, 1, 2), Ok(4));
    assert_eq!(abi::site_entry(&mut port, 1, 2, 0), Ok(0));
    abi::take(&mut port, 0).expect("the second fill");
    assert_eq!(
        &port.mem[..4],
        &[0, 0, 0, 0],
        "nothing of the first remains"
    );
}

/// A refused host call fills nothing.
#[test]
fn a_refusal_leaves_the_register_empty() {
    let (mut port, _) = Port::new(&[]);
    port.host.refuse = true;
    assert_eq!(
        abi::site_get(&mut port, 1, 2),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(abi::take(&mut port, 0), Err(VIOLATION));
}

// ---- memory --------------------------------------------------------------

/// A range that leaves the memory is a violation, wherever it lands,
/// and an offset that wraps is not a range at all.
#[test]
fn a_range_outside_the_memory_is_a_violation() {
    let mut mem = vec![0u8; 256];
    let bytes = mem.as_mut_slice();
    assert!(bytes.read(0, 256).is_ok());
    assert_eq!(bytes.read(0, 257), Err(VIOLATION));
    assert_eq!(bytes.read(256, 1), Err(VIOLATION));
    assert_eq!(bytes.read(u32::MAX, 2), Err(VIOLATION));
    assert!(bytes.write(255, &[1]).is_ok());
    assert_eq!(bytes.write(255, &[1, 2]), Err(VIOLATION));
    assert_eq!(bytes.write(u32::MAX, &[1, 2]), Err(VIOLATION));

    let (mut port, _) = Port::new(&[GuestArg::Bytes(b"four")]);
    assert_eq!(abi::arg(&mut port, 0, 254), Err(VIOLATION));
    assert_eq!(abi::site_set(&mut port, 0, 0, 250, 7), Err(VIOLATION));
    assert!(port.calls().is_empty(), "nothing reached the host");
}

// ---- fixed-width encodings -----------------------------------------------

/// An amount is sixteen little-endian bytes, low half first, both ways.
#[test]
fn an_amount_is_sixteen_bytes_low_then_high() {
    let (mut port, _) = Port::new(&[]);
    port.mem[..16].copy_from_slice(&amount_bytes(AMOUNT));
    assert_eq!(abi::site_take(&mut port, 1, 2, 0), Ok(16));
    assert_eq!(abi::bucket_take(&mut port, 5, 0), Ok(14));
    assert_eq!(abi::mint(&mut port, 0, 0), Ok(11));
    port.mem[16..20].copy_from_slice(b"data");
    abi::site_insert(&mut port, 1, 2, 0, 16, 4).expect("inserts");

    abi::site_balance(&mut port, 1, 2, 100).expect("balance");
    assert_eq!(&port.mem[100..116], &amount_bytes(AMOUNT));
    abi::bucket_amount(&mut port, 5, 120).expect("amount");
    assert_eq!(&port.mem[120..136], &amount_bytes(AMOUNT));
    abi::site_order(&mut port, 1, 2, 0, 140).expect("order");
    assert_eq!(&port.mem[140..156], &amount_bytes(AMOUNT));

    let amount = format!("{AMOUNT:#x}");
    assert_eq!(
        port.calls(),
        [
            format!("site-take(1,2,{amount})"),
            format!("bucket-take(5,{amount})"),
            format!("mint(0,{amount})"),
            format!("site-insert(1,2,{amount},[100, 97, 116, 97])"),
            "site-balance(1,2)".to_owned(),
            "bucket-amount(5)".to_owned(),
            "site-order(1,2,0)".to_owned(),
        ]
    );
}

/// A wide is four little-endian limbs, least significant first, both
/// ways; a rounding is one of two codes and an ordering one of three.
#[test]
fn a_wide_is_four_limbs_and_the_enums_are_their_codes() {
    let (mut port, _) = Port::new(&[]);
    port.mem[..32].copy_from_slice(&limb_bytes(WIDE));
    port.mem[32..64].copy_from_slice(&limb_bytes(U256::from_u128(6)));
    port.mem[64..96].copy_from_slice(&limb_bytes(U256::from_u128(3)));

    assert_eq!(abi::bucket_split(&mut port, 5, 0, 32), Ok(15));
    assert_eq!(port.calls(), ["bucket-split(5,[1, 2, 3, 4],[6, 0, 0, 0])"]);

    // 6 * 3 / 3 = 6, held whole.
    abi::mul_div(&mut port, 32, 64, 64, ROUNDING_DOWN, 128).expect("mul-div");
    assert_eq!(&port.mem[128..160], &limb_bytes(U256::from_u128(6)));
    abi::mul_div(&mut port, 32, 64, 64, ROUNDING_UP, 128).expect("up");
    assert_eq!(
        abi::mul_div(&mut port, 32, 64, 64, 2, 128),
        Err(VIOLATION),
        "a rounding past the enum"
    );
    assert_eq!(abi::fixed_pow(&mut port, 32, 1, 7, 128), Err(VIOLATION));

    // sqrt(6 * 6) = 6.
    abi::geometric_mean(&mut port, 32, 32, 160).expect("mean");
    assert_eq!(&port.mem[160..192], &limb_bytes(U256::from_u128(6)));

    // (6/3) * (3/6) = 18/18.
    abi::fraction_compose(&mut port, 32, 64, 64, 32, 192, 224).expect("compose");
    assert_eq!(&port.mem[192..224], &limb_bytes(U256::from_u128(18)));
    assert_eq!(&port.mem[224..256], &limb_bytes(U256::from_u128(18)));

    // 3/6 < 6/3, and 6/3 > 3/6.
    assert_eq!(
        abi::fraction_cmp(&mut port, 64, 32, 32, 64),
        Ok(ORDERING_LESS)
    );
    assert_eq!(
        abi::fraction_cmp(&mut port, 32, 64, 64, 32),
        Ok(ORDERING_GREATER)
    );
}

/// A drawn is a tag, with the word written only when ready.
#[test]
fn a_drawn_is_a_tag_and_a_word_only_when_ready() {
    let (mut port, _) = Port::new(&[]);
    assert_eq!(abi::site_open_seal(&mut port, 1, 2, 8), Ok(DRAWN_READY));
    assert_eq!(&port.mem[8..40], &WORD);

    for (drawn, tag) in [
        (Drawn::Pending, DRAWN_PENDING),
        (Drawn::Expired, DRAWN_EXPIRED),
    ] {
        let (mut port, _) = Port::new(&[]);
        port.host.drawn = drawn;
        assert_eq!(abi::site_open_seal(&mut port, 1, 2, 8), Ok(tag));
        assert_eq!(&port.mem[8..40], &[0; 32], "nothing written");
    }
}

/// Ids cross as little-endian `u64`s, eight bytes each, counted rather
/// than measured.
#[test]
fn ids_cross_as_counted_little_endian_words() {
    let (mut port, _) = Port::new(&[]);
    port.mem[..8].copy_from_slice(&5u64.to_le_bytes());
    port.mem[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(abi::mint_instances(&mut port, 0, 0, 2), Ok(12));
    assert_eq!(abi::site_instance_take(&mut port, 1, 2, 0, 1), Ok(13));
    assert_eq!(
        abi::site_instance_take(&mut port, 1, 2, 0, u32::MAX),
        Err(VIOLATION),
        "a count whose width overflows"
    );
    assert_eq!(
        port.calls(),
        [
            "mint-instances(0,[5, 18446744073709551615])",
            "site-instance-take(1,2,[5])"
        ]
    );
}

/// A digest is thirty-two bytes at the out-pointer; a clock is a plain
/// `i64`.
#[test]
fn a_digest_lands_at_the_out_pointer() {
    let (mut port, _) = Port::new(&[]);
    port.mem[..3].copy_from_slice(b"abc");
    abi::hash(&mut port, 0, 3, 64).expect("hash");
    assert_eq!(&port.mem[64..96], &[3; 32]);
    assert_eq!(abi::clock(&mut port), 0xDEAD_BEEF_0000_0001);
    assert_eq!(port.calls(), ["hash([97, 98, 99])"]);
}

/// Every byte-carrying argument reaches the host as the bytes at its
/// pointer, and every scalar as itself.
#[test]
fn byte_arguments_reach_the_host_as_written() {
    let (mut port, _) = Port::new(&[]);
    port.mem[..2].copy_from_slice(b"ab");
    abi::site_set(&mut port, 1, 2, 0, 2).expect("set");
    abi::site_entry_set(&mut port, 1, 2, 3, 1, 1).expect("entry-set");
    abi::site_instance_put(&mut port, 1, 2, 9, 0, 0).expect("put");
    abi::emit(&mut port, 4, 0, 2).expect("emit");
    assert_eq!(abi::site_declared(&mut port, 1, 2), Ok(1));
    assert_eq!(abi::site_covered(&mut port, 1, 2), Ok(0));
    abi::bucket_drop(&mut port, 8).expect("drop");
    assert_eq!(
        port.calls(),
        [
            "site-set(1,2,[97, 98])",
            "site-entry-set(1,2,3,[98])",
            "site-instance-put(1,2,9,[])",
            "emit(4,[97, 98])",
            "site-declared(1,2)",
            "site-covered(1,2)",
            "bucket-drop(8)",
        ]
    );
}

// ---- the import table ----------------------------------------------------

/// One entry per import, uniquely named, one for every host operation.
#[test]
fn the_import_table_names_every_import_once() {
    let names: BTreeSet<(&str, &str)> = IMPORTS
        .iter()
        .map(|(module, name, _, _)| (*module, *name))
        .collect();
    assert_eq!(names.len(), IMPORTS.len(), "no import is named twice");
    assert_eq!(IMPORTS.len(), 40);
    assert!(
        IMPORTS.iter().all(|(_, _, _, results)| results.len() <= 1),
        "every import returns at most one value"
    );
}
