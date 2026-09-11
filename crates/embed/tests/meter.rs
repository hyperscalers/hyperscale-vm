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
    /// What the next floor ask reports as owed before the page.
    scan_floor: usize,
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
        self.op("site_len", 0)
    }
    fn site_declared(&mut self, _site: u32, _element: u32) -> Result<bool, AbortReason> {
        self.op("site_declared", true)
    }
    fn site_get(&mut self, _site: u32, _element: u32) -> Result<Vec<u8>, AbortReason> {
        self.op("site_get", vec![0; 5])
    }
    fn site_set(&mut self, _site: u32, _element: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        self.op("site_set", ())
    }
    fn site_clear(&mut self, _site: u32, _element: u32) -> Result<(), AbortReason> {
        self.op("site_clear", ())
    }
    fn site_balance(&mut self, _site: u32, _element: u32) -> Result<u128, AbortReason> {
        self.op("site_balance", 7)
    }
    fn burn(&mut self, _funds: u32) -> Result<(), AbortReason> {
        self.op("burn", ())
    }
    fn mint(&mut self, _grant: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("mint", 1)
    }
    fn mint_instances(&mut self, _grant: u32, _ids: &[u64]) -> Result<u32, AbortReason> {
        self.op("mint_instances", 1)
    }
    fn site_instance_take(
        &mut self,
        _site: u32,
        _element: u32,
        _ids: &[u64],
    ) -> Result<u32, AbortReason> {
        self.op("site_instance_take", 1)
    }
    fn site_instance_put(
        &mut self,
        _site: u32,
        _element: u32,
        _funds: u32,
        _v: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site_instance_put", ())
    }
    fn bucket_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("bucket_take", 1)
    }
    fn bucket_split(&mut self, _rep: u32, _num: U256, _den: U256) -> Result<u32, AbortReason> {
        self.op("bucket_split", 1)
    }
    fn bucket_put(&mut self, _rep: u32, _other: u32) -> Result<(), AbortReason> {
        self.op("bucket_put", ())
    }
    fn bucket_amount(&mut self, _rep: u32) -> Result<u128, AbortReason> {
        self.op("bucket_amount", 7)
    }
    fn site_put(&mut self, _site: u32, _element: u32, _funds: u32) -> Result<(), AbortReason> {
        self.op("site_put", ())
    }
    fn site_take(&mut self, _site: u32, _element: u32, _amount: u128) -> Result<u32, AbortReason> {
        self.op("site_take", 1)
    }
    fn site_reserve_take(&mut self, _site: u32, _element: u32) -> Result<u32, AbortReason> {
        self.op("site_reserve_take", 1)
    }
    fn take_scan_debt(&mut self) -> usize {
        self.log.lock().unwrap().push(Host("take-scan-debt"));
        std::mem::take(&mut self.scan_debt)
    }
    fn scan_floor(&mut self, _site: u32, _element: u32) -> Result<usize, AbortReason> {
        let floor = std::mem::take(&mut self.scan_floor);
        self.op("scan-floor", floor)
    }
    fn site_count(&mut self, _site: u32, _element: u32) -> Result<u32, AbortReason> {
        self.op("site_count", 2)
    }
    fn site_covered(&mut self, _site: u32, _element: u32) -> Result<bool, AbortReason> {
        self.op("site_covered", true)
    }
    fn site_order(&mut self, _site: u32, _element: u32, _index: u32) -> Result<u128, AbortReason> {
        self.op("site_order", 7)
    }
    fn site_entry(
        &mut self,
        _site: u32,
        _element: u32,
        _index: u32,
    ) -> Result<Vec<u8>, AbortReason> {
        self.op("site_entry", vec![0; 9])
    }
    fn site_entry_set(
        &mut self,
        _site: u32,
        _element: u32,
        _i: u32,
        _value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site_entry_set", ())
    }
    fn site_insert(
        &mut self,
        _site: u32,
        _element: u32,
        _o: u128,
        _v: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.op("site_insert", ())
    }
    fn site_remove(&mut self, _site: u32, _element: u32, _index: u32) -> Result<(), AbortReason> {
        self.op("site_remove", ())
    }
    fn bucket_drop(&mut self, _rep: u32) -> Result<(), AbortReason> {
        self.op("bucket_drop", ())
    }
    fn clock_ms(&self) -> u64 {
        0
    }
    fn site_seal(&mut self, _site: u32, _element: u32) -> Result<(), AbortReason> {
        self.op("site_seal", ())
    }
    fn site_open_seal(&mut self, _site: u32, _element: u32) -> Result<Drawn, AbortReason> {
        self.log.lock().unwrap().push(Host("site_open_seal"));
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
                scan_floor: 0,
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
#[allow(clippy::too_many_lines)] // one pinned case per kernel import
fn every_function_charges_its_pinned_sequence() {
    // (what ran, the expected steps) — result bytes after the operation
    // succeeds, argument bytes before it runs, the scan ask between the
    // operation and its refusal, exactly once each.
    let cases: Vec<Case> = vec![
        (
            "site_get",
            |p| {
                let _ = meter::site_get(p, 0, 0);
            },
            vec![Host("site_get"), Charge(5)],
        ),
        (
            "site_seal",
            |p| {
                let _ = meter::site_seal(p, 0, 0);
            },
            vec![Host("site_seal"), Charge(8)],
        ),
        (
            "site_open_seal",
            |p| {
                let _ = meter::site_open_seal(p, 0, 0);
            },
            vec![Host("site_open_seal"), Charge(32)],
        ),
        (
            "site_set",
            |p| {
                let _ = meter::site_set(p, 0, 0, vec![0; 5]);
            },
            vec![Charge(5), Host("site_set")],
        ),
        (
            "site_clear",
            |p| {
                let _ = meter::site_clear(p, 0, 0);
            },
            vec![Host("site_clear")],
        ),
        (
            "mint",
            |p| {
                let _ = meter::mint(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("mint")],
        ),
        (
            "site_balance",
            |p| {
                let _ = meter::site_balance(p, 0, 0);
            },
            vec![Host("site_balance"), Charge(AMOUNT)],
        ),
        (
            "site_take",
            |p| {
                let _ = meter::site_take(p, 0, 0, 1);
            },
            vec![Charge(AMOUNT), Host("site_take")],
        ),
        (
            "burn",
            |p| {
                let _ = meter::burn(p, 1);
            },
            vec![Host("burn")],
        ),
        (
            "bucket_drop",
            |p| {
                let _ = meter::bucket_drop(p, 1);
            },
            vec![Host("bucket_drop")],
        ),
        (
            "mint_instances",
            |p| {
                let _ = meter::mint_instances(p, 0, &[1, 2, 3]);
            },
            vec![Charge(24), Host("mint_instances")],
        ),
        (
            "site_instance_take",
            |p| {
                let _ = meter::site_instance_take(p, 0, 0, &[1, 2, 3]);
            },
            vec![
                Charge(24),
                Host("scan-floor"),
                Host("site_instance_take"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site_instance_put",
            |p| {
                let _ = meter::site_instance_put(p, 0, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("scan-floor"),
                Host("site_instance_put"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "bucket_take",
            |p| {
                let _ = meter::bucket_take(p, 0, 1);
            },
            vec![Charge(AMOUNT), Host("bucket_take")],
        ),
        (
            "bucket_split",
            |p| {
                let _ = meter::bucket_split(p, 0, U256::from(1u128), U256::from(2u128));
            },
            vec![Charge(WIDE * 2), Host("bucket_split")],
        ),
        (
            "bucket_put",
            |p| {
                let _ = meter::bucket_put(p, 0, 1);
            },
            vec![Host("bucket_put")],
        ),
        (
            "bucket_amount",
            |p| {
                let _ = meter::bucket_amount(p, 0);
            },
            vec![Host("bucket_amount"), Charge(AMOUNT)],
        ),
        (
            "site_put",
            |p| {
                let _ = meter::site_put(p, 0, 0, 1);
            },
            vec![Host("site_put")],
        ),
        (
            "site_len",
            |p| {
                let _ = meter::site_len(p, 0);
            },
            vec![Host("site_len")],
        ),
        (
            "site_declared",
            |p| {
                let _ = meter::site_declared(p, 0, 0);
            },
            vec![Host("site_declared")],
        ),
        (
            "site_reserve_take",
            |p| {
                let _ = meter::site_reserve_take(p, 0, 0);
            },
            vec![Host("site_reserve_take")],
        ),
        (
            "site_count",
            |p| {
                let _ = meter::site_count(p, 0, 0);
            },
            vec![
                Host("scan-floor"),
                Host("site_count"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site_covered",
            |p| {
                let _ = meter::site_covered(p, 0, 0);
            },
            vec![
                Host("scan-floor"),
                Host("site_covered"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site_order",
            |p| {
                let _ = meter::site_order(p, 0, 0, 0);
            },
            vec![
                Host("scan-floor"),
                Host("site_order"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(AMOUNT),
            ],
        ),
        (
            "site_entry",
            |p| {
                let _ = meter::site_entry(p, 0, 0, 0);
            },
            vec![
                Host("scan-floor"),
                Host("site_entry"),
                Host("take-scan-debt"),
                Charge(3),
                Charge(9),
            ],
        ),
        (
            "site_entry_set",
            |p| {
                let _ = meter::site_entry_set(p, 0, 0, 0, vec![0; 5]);
            },
            vec![
                Charge(5),
                Host("scan-floor"),
                Host("site_entry_set"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site_insert",
            |p| {
                let _ = meter::site_insert(p, 0, 0, 1, vec![0; 5]);
            },
            vec![
                Charge(AMOUNT + 5),
                Host("scan-floor"),
                Host("site_insert"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "site_remove",
            |p| {
                let _ = meter::site_remove(p, 0, 0, 0);
            },
            vec![
                Host("scan-floor"),
                Host("site_remove"),
                Host("take-scan-debt"),
                Charge(3),
            ],
        ),
        (
            "mul_div",
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
            "geometric_mean",
            |p| {
                let _ = meter::geometric_mean(p, U256::from(1u128), U256::from(2u128));
            },
            vec![Charge(WIDE * 3)],
        ),
        (
            "fraction_compose",
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
            "fraction_cmp",
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
            "fixed_pow",
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
    // scan ask, which is owed whether the call refused or not. A floor
    // ask that refuses stops the sequence there: the page was never
    // asked for.
    let mut probe = Probe::refusing();
    assert_eq!(
        meter::site_get(&mut probe, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("site_get")]);

    let mut probe = Probe::refusing();
    assert_eq!(
        meter::site_balance(&mut probe, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("site_balance")]);

    let mut probe = Probe::refusing();
    probe.host.scan_debt = 3;
    assert_eq!(
        meter::site_entry(&mut probe, 0, 0, 0),
        Err(MeterError::Refused(AbortReason::CellUnderflow))
    );
    assert_eq!(probe.steps(), vec![Host("scan-floor")]);
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

/// The floor of a scan is paid before the store is asked for the page,
/// and a budget that cannot pay it never has the page fetched: the
/// kernel is asked what the walk costs and nothing else.
#[test]
fn the_scan_floor_is_paid_before_the_page() {
    let mut probe = Probe::new(3);
    probe.host.scan_floor = 7;
    assert_eq!(meter::site_count(&mut probe, 0, 0), Ok(2));
    assert_eq!(
        probe.steps(),
        vec![
            Host("scan-floor"),
            Charge(7),
            Host("site_count"),
            Host("take-scan-debt"),
            Charge(3),
        ]
    );

    let mut probe = Probe::new(3);
    probe.host.scan_floor = 7;
    probe.remaining = Some(6);
    assert_eq!(
        meter::site_count(&mut probe, 0, 0),
        Err(MeterError::Exhausted)
    );
    assert_eq!(probe.steps(), vec![Host("scan-floor"), Charge(7)]);
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
