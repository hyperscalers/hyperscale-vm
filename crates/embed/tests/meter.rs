//! The cost model, pinned.
//!
//! Both engines price the boundary through one table, so no differential
//! lane can catch the table itself drifting — a wrong price or a reordered
//! charge changes both sides together and they agree on the wrong figure.
//! This lane is the pin: every metered function's charges, and where each
//! falls relative to the host operation, asserted as a sequence.

use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::meter::{
    self, AMOUNT_BOUNDARY_BYTES, Exhausted, FuelSink, HostAccess, MeterError, WIDE_BOUNDARY_BYTES,
};
use hyperscale_vm_types::math::{MathError, Rounding, U256};
use hyperscale_vm_types::{AbortReason, Drawn};

/// One observed step: a fuel charge, or a host operation by name.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Charge(u64),
    Host(&'static str),
}

use Step::{Charge, Host};

type Log = Arc<Mutex<Vec<Step>>>;

/// A host whose every operation answers a canned value and logs itself.
struct StubHost {
    log: Log,
    /// What the next scan ask reports as lifted.
    scan_debt: usize,
    /// Whether operations refuse instead of answering.
    refuse: bool,
}

impl StubHost {
    fn op<T>(&self, name: &'static str, value: T) -> Result<T, AbortReason> {
        self.log.lock().unwrap().push(Host(name));
        if self.refuse {
            Err(AbortReason::CellUnderflow)
        } else {
            Ok(value)
        }
    }
}

impl KernelHost for StubHost {
    fn run_len(&mut self, _rep: u32) -> Result<u32, AbortReason> {
        self.op("run-len", 0)
    }
    fn run_declared(&mut self, _rep: u32, _index: u32) -> Result<bool, AbortReason> {
        self.op("run-declared", true)
    }
    fn run_at(&mut self, _rep: u32, index: u32) -> Result<u32, AbortReason> {
        self.op("run-at", index)
    }
    fn read_cell(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        self.op("read-cell", vec![0; 5])
    }
    fn write_cell_get(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        self.op("write-cell-get", vec![0; 5])
    }
    fn write_cell_set(&mut self, _rep: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        self.op("write-cell-set", ())
    }
    fn write_cell_clear(&mut self, _rep: u32) -> Result<(), AbortReason> {
        self.op("write-cell-clear", ())
    }
    fn amount_cell_balance(&mut self, _rep: u32) -> Result<u128, AbortReason> {
        self.op("balance", 7)
    }
    fn burn(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
        self.op("burn", ())
    }
    fn mint(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("mint", 1)
    }
    fn mint_instances(&mut self, _rep: u32, _ids: &[u64]) -> Result<u32, AbortReason> {
        self.op("mint-instances", 1)
    }
    fn range_take(&mut self, _rep: u32, _ids: &[u64]) -> Result<u32, AbortReason> {
        self.op("range-take", 1)
    }
    fn range_put(&mut self, _rep: u32, _funds: u32, _v: Vec<u8>) -> Result<(), AbortReason> {
        self.op("range-put", ())
    }
    fn bucket_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("bucket-take", 1)
    }
    fn bucket_split(&mut self, _rep: u32, _num: U256, _den: U256) -> Result<u32, AbortReason> {
        self.op("bucket-split", 1)
    }
    fn bucket_put(&mut self, _rep: u32, _other: u32) -> Result<(), AbortReason> {
        self.op("bucket-put", ())
    }
    fn bucket_amount(&mut self, _rep: u32) -> Result<u128, AbortReason> {
        self.op("bucket-amount", 7)
    }
    fn delta_put(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
        self.op("delta-put", ())
    }
    fn write_put(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
        self.op("write-put", ())
    }
    fn delta_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("delta-take", 1)
    }
    fn write_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("write-take", 1)
    }
    fn reserve_take(&mut self, _rep: u32) -> Result<u32, AbortReason> {
        self.op("reserve-take", 1)
    }
    fn take_scan_debt(&mut self) -> usize {
        self.log.lock().unwrap().push(Host("take-scan-debt"));
        std::mem::take(&mut self.scan_debt)
    }
    fn range_count(&mut self, _rep: u32) -> Result<u32, AbortReason> {
        self.op("range-count", 2)
    }
    fn range_covered(&mut self, _rep: u32) -> Result<bool, AbortReason> {
        self.op("range-covered", true)
    }
    fn range_order(&mut self, _rep: u32, _index: u32) -> Result<u128, AbortReason> {
        self.op("range-order", 7)
    }
    fn range_entry(&mut self, _rep: u32, _index: u32) -> Result<Vec<u8>, AbortReason> {
        self.op("range-entry", vec![0; 9])
    }
    fn range_set(&mut self, _rep: u32, _i: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        self.op("range-set", ())
    }
    fn range_insert(&mut self, _rep: u32, _o: u128, _v: Vec<u8>) -> Result<(), AbortReason> {
        self.op("range-insert", ())
    }
    fn range_remove(&mut self, _rep: u32, _index: u32) -> Result<(), AbortReason> {
        self.op("range-remove", ())
    }
    fn bucket_drop(&mut self, _rep: u32) -> Result<(), AbortReason> {
        self.op("bucket-drop", ())
    }
    fn clock_ms(&self) -> u64 {
        0
    }
    fn seal(&mut self, _rep: u32) -> Result<(), AbortReason> {
        self.op("seal", ())
    }
    fn open_seal(&mut self, _rep: u32) -> Result<Drawn, AbortReason> {
        self.log.lock().unwrap().push(Host("open-seal"));
        Ok(Drawn::Ready([0; 32]))
    }
    fn hash(&self, _data: &[u8]) -> [u8; 32] {
        self.log.lock().unwrap().push(Host("hash"));
        [0; 32]
    }
    fn emit(&mut self, _event_type: u32, _payload: Vec<u8>) -> Result<(), AbortReason> {
        self.op("emit", ())
    }
}

/// The two capabilities over one log, with an optional budget.
struct Probe {
    host: StubHost,
    log: Log,
    remaining: Option<u64>,
}

impl Probe {
    fn new(scan_debt: usize) -> Self {
        let log = Log::default();
        Self {
            host: StubHost {
                log: Arc::clone(&log),
                scan_debt,
                refuse: false,
            },
            log,
            remaining: None,
        }
    }

    fn refusing() -> Self {
        let mut probe = Self::new(0);
        probe.host.refuse = true;
        probe
    }

    fn steps(&self) -> Vec<Step> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

impl HostAccess for Probe {
    type Host = StubHost;

    fn host(&mut self) -> &mut StubHost {
        &mut self.host
    }
}

impl FuelSink for Probe {
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted> {
        self.log.lock().unwrap().push(Charge(fuel));
        let Some(left) = &mut self.remaining else {
            return Ok(());
        };
        *left = left.checked_sub(fuel).ok_or(Exhausted)?;
        Ok(())
    }
}

const AMOUNT: u64 = AMOUNT_BOUNDARY_BYTES as u64;
const WIDE: u64 = WIDE_BOUNDARY_BYTES as u64;

type Case = (&'static str, fn(&mut Probe), Vec<Step>);

#[test]
#[allow(clippy::too_many_lines)] // one pinned case per world function
fn every_function_charges_its_pinned_sequence() {
    // (what ran, the expected steps) — result bytes after the operation
    // succeeds, argument bytes before it runs, the scan ask between the
    // operation and its refusal, exactly once each.
    let cases: Vec<Case> = vec![
        (
            "read-cell-get",
            |p| {
                let _ = meter::read_cell_get(p, 0);
            },
            vec![Host("read-cell"), Charge(5)],
        ),
        (
            "write-cell-get",
            |p| {
                let _ = meter::write_cell_get(p, 0);
            },
            vec![Host("write-cell-get"), Charge(5)],
        ),
        (
            "write-cell-seal",
            |p| {
                let _ = meter::seal(p, 0);
            },
            vec![Host("seal"), Charge(8)],
        ),
        (
            "write-cell-open-seal",
            |p| {
                let _ = meter::open_seal(p, 0);
            },
            vec![Host("open-seal"), Charge(32)],
        ),
        (
            "write-cell-set",
            |p| {
                let _ = meter::write_cell_set(p, 0, vec![0; 5]);
            },
            vec![Charge(5), Host("write-cell-set")],
        ),
        (
            "write-cell-clear",
            |p| {
                let _ = meter::write_cell_clear(p, 0);
            },
            vec![Host("write-cell-clear")],
        ),
        (
            "mint",
            |p| {
                let _ = meter::mint(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("mint")],
        ),
        (
            "amount-balance",
            |p| {
                let _ = meter::amount_balance(p, 0);
            },
            vec![Host("balance"), Charge(AMOUNT)],
        ),
        (
            "amount-cell-take",
            |p| {
                let _ = meter::amount_cell_take(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("write-take")],
        ),
        (
            "burn",
            |p| {
                let _ = meter::burn(p, 0, 1);
            },
            vec![Host("burn")],
        ),
        (
            "mint-instances",
            |p| {
                let _ = meter::mint_instances(p, 0, &[1, 2, 3]);
            },
            vec![Charge(24), Host("mint-instances")],
        ),
        (
            "instance-range-take",
            |p| {
                let _ = meter::instance_range_take(p, 0, &[1, 2, 3]);
            },
            vec![
                Charge(24),
                Host("range-take"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "instance-range-put",
            |p| {
                let _ = meter::instance_range_put(p, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("range-put"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "bucket-take",
            |p| {
                let _ = meter::bucket_take(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("bucket-take")],
        ),
        (
            "bucket-split",
            |p| {
                let _ = meter::bucket_split(p, 0, U256::from(1u128), U256::from(2u128));
            },
            vec![Charge(WIDE * 2), Host("bucket-split")],
        ),
        (
            "bucket-put",
            |p| {
                let _ = meter::bucket_put(p, 0, 1);
            },
            vec![Host("bucket-put")],
        ),
        (
            "bucket-amount",
            |p| {
                let _ = meter::bucket_amount(p, 0);
            },
            vec![Host("bucket-amount"), Charge(AMOUNT)],
        ),
        (
            "amount-cell-put",
            |p| {
                let _ = meter::amount_cell_put(p, 0, 1);
            },
            vec![Host("write-put")],
        ),
        (
            "delta-cell-put",
            |p| {
                let _ = meter::delta_cell_put(p, 0, 1);
            },
            vec![Host("delta-put")],
        ),
        (
            "delta-cell-take",
            |p| {
                let _ = meter::delta_cell_take(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("delta-take")],
        ),
        (
            "reserve-cell-take",
            |p| {
                let _ = meter::reserve_cell_take(p, 0);
            },
            vec![Host("reserve-take")],
        ),
        (
            "range-count",
            |p| {
                let _ = meter::range_count(p, 0);
            },
            vec![Host("range-count"), Host("take-scan-debt"), Charge(3)],
        ),
        (
            "range-covered",
            |p| {
                let _ = meter::range_covered(p, 0);
            },
            vec![Host("range-covered"), Host("take-scan-debt"), Charge(3)],
        ),
        (
            "range-order",
            |p| {
                let _ = meter::range_order(p, 0, 0);
            },
            vec![
                Host("range-order"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(AMOUNT),
            ],
        ),
        (
            "range-entry",
            |p| {
                let _ = meter::range_entry(p, 0, 0);
            },
            vec![
                Host("range-entry"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(9),
            ],
        ),
        (
            "range-set",
            |p| {
                let _ = meter::range_set(p, 0, 0, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("range-set"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "range-insert",
            |p| {
                let _ = meter::range_insert(p, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(AMOUNT + 5),
                Host("range-insert"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "range-remove",
            |p| {
                let _ = meter::range_remove(p, 0, 0);
            },
            vec![Host("range-remove"), Host("take-scan-debt"), Charge(3)],
        ),
        (
            "mul-div",
            |p| {
                let _ = meter::mul_div(
                    p,
                    U256::from(1u128),
                    U256::from(2u128),
                    U256::from(3u128),
                    Rounding::Down,
                );
            },
            vec![Charge(WIDE * 4)],
        ),
        (
            "geometric-mean",
            |p| {
                let _ = meter::geometric_mean(p, U256::from(1u128), U256::from(2u128));
            },
            vec![Charge(WIDE * 3)],
        ),
        (
            "fraction-compose",
            |p| {
                let _ = meter::fraction_compose(
                    p,
                    U256::from(1u128),
                    U256::from(2u128),
                    U256::from(3u128),
                    U256::from(4u128),
                );
            },
            vec![Charge(WIDE * 6)],
        ),
        (
            "fraction-cmp",
            |p| {
                let _ = meter::fraction_cmp(
                    p,
                    U256::from(1u128),
                    U256::from(2u128),
                    U256::from(3u128),
                    U256::from(4u128),
                );
            },
            vec![Charge(WIDE * 4)],
        ),
        (
            "fixed-pow",
            |p| {
                let _ = meter::fixed_pow(p, U256::from(1u128), 2, Rounding::Down);
            },
            vec![Charge(WIDE * 2)],
        ),
        (
            "hash",
            |p| {
                let _ = meter::hash(p, &[0; 5]);
            },
            vec![Host("hash"), Charge(37)],
        ),
        (
            "emit",
            |p| {
                let _ = meter::emit(p, 0, vec![0; 5]);
            },
            vec![Charge(5), Host("emit")],
        ),
    ];

    for (name, run, expected) in cases {
        let mut probe = Probe::new(3);
        run(&mut probe);
        assert_eq!(probe.steps(), expected, "{name} charged off its pin");
    }
}

#[test]
fn a_refusal_charges_no_result_bytes() {
    // "Result bytes after it succeeds": a refused operation crossed
    // nothing back, so the sequence stops at the operation — except the
    // scan ask, which is owed whether the call refused or not.
    let mut probe = Probe::refusing();
    assert_eq!(
        meter::read_cell_get(&mut probe, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("read-cell")]);

    let mut probe = Probe::refusing();
    assert_eq!(
        meter::amount_balance(&mut probe, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("balance")]);

    let mut probe = Probe::refusing();
    probe.host.scan_debt = 3;
    assert_eq!(
        meter::range_entry(&mut probe, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(
        probe.steps(),
        vec![Host("range-entry"), Host("take-scan-debt"), Charge(3)]
    );
}

#[test]
fn exhaustion_stops_the_sequence_where_it_lands() {
    // An argument charge past the budget refuses before the operation
    // runs: the kernel is never asked.
    let mut probe = Probe::new(0);
    probe.remaining = Some(4);
    assert_eq!(
        meter::write_cell_set(&mut probe, 0, vec![0; 5]),
        Err(MeterError::Exhausted)
    );
    assert_eq!(probe.steps(), vec![Charge(5)]);
}

#[test]
fn the_math_error_classes_cross_unchanged() {
    let mut probe = Probe::new(0);
    assert_eq!(
        meter::mul_div(
            &mut probe,
            U256::from(1u128),
            U256::from(2u128),
            U256::from(0u128),
            Rounding::Down,
        ),
        Err(MeterError::Refused(MathError::DivideByZero.into()))
    );
    let mut probe = Probe::new(0);
    assert_eq!(
        meter::fraction_cmp(
            &mut probe,
            U256::from(1u128),
            U256::from(2u128),
            U256::from(3u128),
            U256::from(4u128),
        )
        .map(|order| order == Ordering::Less),
        Ok(true)
    );
}
