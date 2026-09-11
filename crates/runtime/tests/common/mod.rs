//! A small kernel for the core-module tests: enough state to move value
//! and bytes through every import, and a log of what reached it.

#![allow(dead_code)] // each test file uses the part of the kernel it exercises

use std::fmt::Write as _;

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::abi::{CoreType, IMPORTS};
use hyperscale_vm_types::math::U256;
use hyperscale_vm_types::{AbortReason, Drawn};

/// The clock every test kernel reports.
pub const CLOCK_MS: u64 = 0x0102_0304_0506_0708;

/// What the reserve at any site grants.
pub const RESERVE: u128 = 5;

/// What a bucket holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Held {
    Amount(u128),
    Ids(Vec<u64>),
    Gone,
}

/// The test kernel: per-site bytes, balances and entries; a bucket
/// table; what was emitted; and every call by name.
#[derive(Clone, Debug)]
pub struct Kernel {
    pub values: Vec<Vec<u8>>,
    pub balances: Vec<u128>,
    pub entries: Vec<Vec<(u128, Vec<u8>)>>,
    pub sealed: Vec<bool>,
    pub buckets: Vec<Held>,
    pub emitted: Vec<(u32, Vec<u8>)>,
    pub drawn: Drawn,
    pub calls: Vec<String>,
}

impl Kernel {
    /// Three sites, each with bytes, a balance and two entries, and two
    /// buckets of value.
    pub fn seeded() -> Self {
        Self {
            values: vec![b"alpha".to_vec(), b"beta".to_vec(), Vec::new()],
            balances: vec![100, 200, 300],
            entries: vec![
                vec![(1, b"one".to_vec()), (2, b"two".to_vec())],
                vec![],
                vec![],
            ],
            sealed: vec![false; 3],
            buckets: vec![Held::Amount(40), Held::Amount(60)],
            emitted: Vec::new(),
            drawn: Drawn::Ready([0xA5; 32]),
            calls: Vec::new(),
        }
    }

    fn note(&mut self, call: impl Into<String>) {
        self.calls.push(call.into());
    }

    const fn site(&self, site: u32) -> Result<usize, AbortReason> {
        let index = site as usize;
        if index < self.values.len() {
            Ok(index)
        } else {
            Err(AbortReason::HandleUnknown)
        }
    }

    fn amount(&self, rep: u32) -> Result<u128, AbortReason> {
        match self.buckets.get(rep as usize) {
            Some(Held::Amount(amount)) => Ok(*amount),
            _ => Err(AbortReason::HandleUnknown),
        }
    }

    fn ids(&self, rep: u32) -> Result<Vec<u64>, AbortReason> {
        match self.buckets.get(rep as usize) {
            Some(Held::Ids(ids)) => Ok(ids.clone()),
            _ => Err(AbortReason::HandleUnknown),
        }
    }

    fn seat(&mut self, held: Held) -> u32 {
        self.buckets.push(held);
        u32::try_from(self.buckets.len() - 1).expect("few buckets")
    }

    fn retire(&mut self, rep: u32) {
        self.buckets[rep as usize] = Held::Gone;
    }
}

impl KernelHost for Kernel {
    fn site_len(&mut self, site: u32) -> Result<u32, AbortReason> {
        self.note(format!("site_len({site})"));
        self.site(site).map(|_| 1)
    }

    fn site_declared(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        self.note(format!("site_declared({site},{element})"));
        self.site(site).map(|_| element == 0)
    }

    fn site_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, AbortReason> {
        self.note(format!("site_get({site},{element})"));
        let index = self.site(site)?;
        Ok(self.values[index].clone())
    }

    fn site_set(&mut self, site: u32, element: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        self.note(format!("site_set({site},{element},{value:?})"));
        let index = self.site(site)?;
        self.values[index] = value;
        Ok(())
    }

    fn site_clear(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        self.note(format!("site_clear({site},{element})"));
        let index = self.site(site)?;
        self.values[index].clear();
        Ok(())
    }

    fn site_balance(&mut self, site: u32, element: u32) -> Result<u128, AbortReason> {
        self.note(format!("site_balance({site},{element})"));
        let index = self.site(site)?;
        Ok(self.balances[index])
    }

    fn burn(&mut self, funds: u32) -> Result<(), AbortReason> {
        self.note(format!("burn({funds})"));
        self.amount(funds)?;
        self.retire(funds);
        Ok(())
    }

    fn mint(&mut self, grant: u32, amount: u128) -> Result<u32, AbortReason> {
        self.note(format!("mint({grant},{amount})"));
        Ok(self.seat(Held::Amount(amount)))
    }

    fn mint_instances(&mut self, grant: u32, ids: &[u64]) -> Result<u32, AbortReason> {
        self.note(format!("mint_instances({grant},{ids:?})"));
        Ok(self.seat(Held::Ids(ids.to_vec())))
    }

    fn site_instance_take(
        &mut self,
        site: u32,
        element: u32,
        ids: &[u64],
    ) -> Result<u32, AbortReason> {
        self.note(format!("site_instance_take({site},{element},{ids:?})"));
        let index = self.site(site)?;
        for id in ids {
            let at = self.entries[index]
                .iter()
                .position(|(order, _)| *order == u128::from(*id))
                .ok_or(AbortReason::HandleUnknown)?;
            self.entries[index].remove(at);
        }
        Ok(self.seat(Held::Ids(ids.to_vec())))
    }

    fn site_instance_put(
        &mut self,
        site: u32,
        element: u32,
        funds: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.note(format!(
            "site_instance_put({site},{element},{funds},{value:?})"
        ));
        let index = self.site(site)?;
        let ids = self.ids(funds)?;
        for id in ids {
            self.entries[index].push((u128::from(id), value.clone()));
        }
        self.entries[index].sort();
        self.retire(funds);
        Ok(())
    }

    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        self.note(format!("bucket_take({rep},{amount})"));
        let held = self.amount(rep)?;
        let left = held.checked_sub(amount).ok_or(AbortReason::CellUnderflow)?;
        self.buckets[rep as usize] = Held::Amount(left);
        Ok(self.seat(Held::Amount(amount)))
    }

    fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, AbortReason> {
        self.note(format!(
            "bucket_split({rep},{:?},{:?})",
            num.limbs(),
            den.limbs()
        ));
        let held = self.amount(rep)?;
        let (Some(num), Some(den)) = (num.to_u128(), den.to_u128()) else {
            return Err(AbortReason::CellUnderflow);
        };
        if den == 0 || num > den {
            return Err(AbortReason::CellUnderflow);
        }
        let off = held * num / den;
        self.buckets[rep as usize] = Held::Amount(held - off);
        Ok(self.seat(Held::Amount(off)))
    }

    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason> {
        self.note(format!("bucket_put({rep},{other})"));
        let into = self.amount(rep)?;
        let from = self.amount(other)?;
        self.buckets[rep as usize] = Held::Amount(into + from);
        self.retire(other);
        Ok(())
    }

    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason> {
        self.note(format!("bucket_amount({rep})"));
        self.amount(rep)
    }

    fn site_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), AbortReason> {
        self.note(format!("site_put({site},{element},{funds})"));
        let index = self.site(site)?;
        let amount = self.amount(funds)?;
        self.balances[index] += amount;
        self.retire(funds);
        Ok(())
    }

    fn site_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, AbortReason> {
        self.note(format!("site_take({site},{element},{amount})"));
        let index = self.site(site)?;
        let left = self.balances[index]
            .checked_sub(amount)
            .ok_or(AbortReason::CellUnderflow)?;
        self.balances[index] = left;
        Ok(self.seat(Held::Amount(amount)))
    }

    fn site_reserve_take(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        self.note(format!("site_reserve_take({site},{element})"));
        self.site(site)?;
        Ok(self.seat(Held::Amount(RESERVE)))
    }

    fn take_scan_debt(&mut self) -> usize {
        0
    }

    fn scan_floor(&mut self, _site: u32, _element: u32) -> Result<usize, AbortReason> {
        Ok(0)
    }

    fn site_count(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        self.note(format!("site_count({site},{element})"));
        let index = self.site(site)?;
        Ok(u32::try_from(self.entries[index].len()).expect("few entries"))
    }

    fn site_covered(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        self.note(format!("site_covered({site},{element})"));
        self.site(site).map(|_| true)
    }

    fn site_order(&mut self, site: u32, element: u32, index: u32) -> Result<u128, AbortReason> {
        self.note(format!("site_order({site},{element},{index})"));
        let at = self.site(site)?;
        self.entries[at]
            .get(index as usize)
            .map(|(order, _)| *order)
            .ok_or(AbortReason::HandleUnknown)
    }

    fn site_entry(&mut self, site: u32, element: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
        self.note(format!("site_entry({site},{element},{index})"));
        let at = self.site(site)?;
        self.entries[at]
            .get(index as usize)
            .map(|(_, value)| value.clone())
            .ok_or(AbortReason::HandleUnknown)
    }

    fn site_entry_set(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.note(format!(
            "site_entry_set({site},{element},{index},{value:?})"
        ));
        let at = self.site(site)?;
        let entry = self.entries[at]
            .get_mut(index as usize)
            .ok_or(AbortReason::HandleUnknown)?;
        entry.1 = value;
        Ok(())
    }

    fn site_insert(
        &mut self,
        site: u32,
        element: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        self.note(format!("site_insert({site},{element},{order},{value:?})"));
        let at = self.site(site)?;
        self.entries[at].retain(|(existing, _)| *existing != order);
        self.entries[at].push((order, value));
        self.entries[at].sort();
        Ok(())
    }

    fn site_remove(&mut self, site: u32, element: u32, index: u32) -> Result<(), AbortReason> {
        self.note(format!("site_remove({site},{element},{index})"));
        let at = self.site(site)?;
        if (index as usize) < self.entries[at].len() {
            self.entries[at].remove(index as usize);
            Ok(())
        } else {
            Err(AbortReason::HandleUnknown)
        }
    }

    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
        self.note(format!("bucket_drop({rep})"));
        if (rep as usize) < self.buckets.len() {
            self.retire(rep);
            Ok(())
        } else {
            Err(AbortReason::HandleUnknown)
        }
    }

    fn clock_ms(&self) -> u64 {
        CLOCK_MS
    }

    fn site_seal(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        self.note(format!("site_seal({site},{element})"));
        let at = self.site(site)?;
        self.sealed[at] = true;
        Ok(())
    }

    fn site_open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, AbortReason> {
        self.note(format!("site_open_seal({site},{element})"));
        self.site(site)?;
        Ok(self.drawn)
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let sum = data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        [sum; 32]
    }

    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason> {
        self.note(format!("emit({event_type},{payload:?})"));
        self.emitted.push((event_type, payload));
        Ok(())
    }
}

/// The identifier a test module binds an import under: the kernel's
/// name with its dashes as underscores.
pub fn ident(name: &str) -> String {
    format!("${}", name.replace('-', "_"))
}

const fn wat_type(ty: CoreType) -> &'static str {
    match ty {
        CoreType::I32 => "i32",
        CoreType::I64 => "i64",
    }
}

/// One import as the kernel defines it, in text.
pub fn import_wat(module: &str, name: &str, params: &[CoreType], results: &[CoreType]) -> String {
    let mut out = format!("  (import \"{module}\" \"{name}\" (func {}", ident(name));
    for param in params {
        let _ = write!(out, " (param {})", wat_type(*param));
    }
    for result in results {
        let _ = write!(out, " (result {})", wat_type(*result));
    }
    out.push_str("))\n");
    out
}

/// Every kernel import, in text, at the type the kernel defines it.
pub fn every_import() -> String {
    IMPORTS
        .iter()
        .map(|(module, name, params, results)| import_wat(module, name, params, results))
        .collect()
}

/// A module importing the whole kernel, exporting its memory, and
/// carrying `body`.
pub fn module(body: &str) -> String {
    format!(
        "(module\n{}  (memory (export \"memory\") 1 1)\n{body})",
        every_import()
    )
}
