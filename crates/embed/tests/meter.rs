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
    fn site_len(&mut self, _site: u32) -> Result<u32, AbortReason> {
        self.op("site-len", 0)
    }
    fn site_declared(&mut self, _site: u32, _element: u32) -> Result<bool, AbortReason> {
        self.op("site-declared", true)
    }
    fn site_get(&mut self, _site: u32, _element: u32) -> Result<Vec<u8>, AbortReason> {
        self.op("site-get", vec![0; 5])
    }
    fn site_set(&mut self, _site: u32, _element: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        self.op("site-set", ())
    }
    fn site_clear(&mut self, _site: u32, _element: u32) -> Result<(), AbortReason> {
        self.op("site-clear", ())
    }
    fn site_balance(&mut self, _site: u32, _element: u32) -> Result<u128, AbortReason> {
        self.op("site-balance", 7)
    }
    fn burn(&mut self, _funds: u32) -> Result<(), AbortReason> {
        self.op("burn", ())
    }
    fn mint(&mut self, _amount: u128) -> Result<u32, AbortReason> {
        self.op("mint", 1)
    }
    fn mint_instances(&mut self, _ids: &[u64]) -> Result<u32, AbortReason> {
        self.op("mint-instances", 1)
    }
    fn site_instance_take(
        &mut self,
        _site: u32,
        _element: u32,
        _ids: &[u64],
    ) -> Result<u32, AbortReason> {
        self.op("site-instance-take", 1)
    }
    fn site_instance_put(
        &mut self,
        _site: u32,
        _element: u32,
        _funds: u32,
        _v: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site-instance-put", ())
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
    fn site_put(&mut self, _site: u32, _element: u32, _funds: u32) -> Result<(), AbortReason> {
        self.op("site-put", ())
    }
    fn site_take(&mut self, _site: u32, _element: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("site-take", 1)
    }
    fn site_reserve_take(&mut self, _site: u32, _element: u32) -> Result<u32, AbortReason> {
        self.op("site-reserve-take", 1)
    }
    fn take_scan_debt(&mut self) -> usize {
        self.log.lock().unwrap().push(Host("take-scan-debt"));
        std::mem::take(&mut self.scan_debt)
    }
    fn site_count(&mut self, _site: u32, _element: u32) -> Result<u32, AbortReason> {
        self.op("site-count", 2)
    }
    fn site_covered(&mut self, _site: u32, _element: u32) -> Result<bool, AbortReason> {
        self.op("site-covered", true)
    }
    fn site_order(&mut self, _site: u32, _element: u32, _index: u32) -> Result<u128, AbortReason> {
        self.op("site-order", 7)
    }
    fn site_entry(
        &mut self,
        _site: u32,
        _element: u32,
        _index: u32,
    ) -> Result<Vec<u8>, AbortReason> {
        self.op("site-entry", vec![0; 9])
    }
    fn site_entry_set(
        &mut self,
        _site: u32,
        _element: u32,
        _i: u32,
        _value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site-entry-set", ())
    }
    fn site_insert(
        &mut self,
        _site: u32,
        _element: u32,
        _o: u128,
        _v: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site-insert", ())
    }
    fn site_remove(&mut self, _site: u32, _element: u32, _index: u32) -> Result<(), AbortReason> {
        self.op("site-remove", ())
    }
    fn bucket_drop(&mut self, _rep: u32) -> Result<(), AbortReason> {
        self.op("bucket-drop", ())
    }
    fn clock_ms(&self) -> u64 {
        0
    }
    fn site_seal(&mut self, _site: u32, _element: u32) -> Result<(), AbortReason> {
        self.op("site-seal", ())
    }
    fn site_open_seal(&mut self, _site: u32, _element: u32) -> Result<Drawn, AbortReason> {
        self.log.lock().unwrap().push(Host("site-open-seal"));
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
            "site-get",
            |p| {
                let _ = meter::site_get(p, 0, 0);
            },
            vec![Host("site-get"), Charge(5)],
        ),
        (
            "site-seal",
            |p| {
                let _ = meter::site_seal(p, 0, 0);
            },
            vec![Host("site-seal"), Charge(8)],
        ),
        (
            "site-open-seal",
            |p| {
                let _ = meter::site_open_seal(p, 0, 0);
            },
            vec![Host("site-open-seal"), Charge(32)],
        ),
        (
            "site-set",
            |p| {
                let _ = meter::site_set(p, 0, 0, vec![0; 5]);
            },
            vec![Charge(5), Host("site-set")],
        ),
        (
            "site-clear",
            |p| {
                let _ = meter::site_clear(p, 0, 0);
            },
            vec![Host("site-clear")],
        ),
        (
            "mint",
            |p| {
                let _ = meter::mint(p, 1);
            },
            vec![Charge(AMOUNT), Host("mint")],
        ),
        (
            "site-balance",
            |p| {
                let _ = meter::site_balance(p, 0, 0);
            },
            vec![Host("site-balance"), Charge(AMOUNT)],
        ),
        (
            "site-take",
            |p| {
                let _ = meter::site_take(p, 0, 0, 1);
            },
            vec![Charge(AMOUNT), Host("site-take")],
        ),
        (
            "burn",
            |p| {
                let _ = meter::burn(p, 1);
            },
            vec![Host("burn")],
        ),
        (
            "mint-instances",
            |p| {
                let _ = meter::mint_instances(p, &[1, 2, 3]);
            },
            vec![Charge(24), Host("mint-instances")],
        ),
        (
            "site-instance-take",
            |p| {
                let _ = meter::site_instance_take(p, 0, 0, &[1, 2, 3]);
            },
            vec![
                Charge(24),
                Host("site-instance-take"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site-instance-put",
            |p| {
                let _ = meter::site_instance_put(p, 0, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("site-instance-put"),
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
            "site-put",
            |p| {
                let _ = meter::site_put(p, 0, 0, 1);
            },
            vec![Host("site-put")],
        ),
        (
            "site-reserve-take",
            |p| {
                let _ = meter::site_reserve_take(p, 0, 0);
            },
            vec![Host("site-reserve-take")],
        ),
        (
            "site-count",
            |p| {
                let _ = meter::site_count(p, 0, 0);
            },
            vec![Host("site-count"), Host("take-scan-debt"), Charge(3)],
        ),
        (
            "site-covered",
            |p| {
                let _ = meter::site_covered(p, 0, 0);
            },
            vec![Host("site-covered"), Host("take-scan-debt"), Charge(3)],
        ),
        (
            "site-order",
            |p| {
                let _ = meter::site_order(p, 0, 0, 0);
            },
            vec![
                Host("site-order"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(AMOUNT),
            ],
        ),
        (
            "site-entry",
            |p| {
                let _ = meter::site_entry(p, 0, 0, 0);
            },
            vec![
                Host("site-entry"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(9),
            ],
        ),
        (
            "site-entry-set",
            |p| {
                let _ = meter::site_entry_set(p, 0, 0, 0, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("site-entry-set"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site-insert",
            |p| {
                let _ = meter::site_insert(p, 0, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(AMOUNT + 5),
                Host("site-insert"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site-remove",
            |p| {
                let _ = meter::site_remove(p, 0, 0, 0);
            },
            vec![Host("site-remove"), Host("take-scan-debt"), Charge(3)],
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
        meter::site_get(&mut probe, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("site-get")]);

    let mut probe = Probe::refusing();
    assert_eq!(
        meter::site_balance(&mut probe, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("site-balance")]);

    let mut probe = Probe::refusing();
    probe.host.scan_debt = 3;
    assert_eq!(
        meter::site_entry(&mut probe, 0, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(
        probe.steps(),
        vec![Host("site-entry"), Host("take-scan-debt"), Charge(3)]
    );
}

#[test]
fn exhaustion_stops_the_sequence_where_it_lands() {
    // An argument charge past the budget refuses before the operation
    // runs: the kernel is never asked.
    let mut probe = Probe::new(0);
    probe.remaining = Some(4);
    assert_eq!(
        meter::site_set(&mut probe, 0, 0, vec![0; 5]),
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
