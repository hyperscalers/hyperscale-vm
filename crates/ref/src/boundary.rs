//! The interpreter at the core boundary.
//!
//! A module the kernel calls directly: its imports resolve by `(module,
//! name)` to the dispatch [`hyperscale_vm_embed::abi`] states once, and
//! the interpreter contributes what an engine contributes — its memory,
//! the counter the meter's pass defined in the module, and the host it
//! was handed — as one [`Boundary`]. What stays the interpreter's own is
//! execution.

use hyperscale_vm_embed::abi::{
    self, Boundary, CoreType, CoreValue, GuestMemory, IMPORTS, MEMORY, Registers,
};
use hyperscale_vm_embed::meter::{Exhausted, FuelSink, HostAccess, MeterError};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked, KernelHost};
use hyperscale_vm_meter::{EXHAUST, FUEL, NAMESPACE};
use hyperscale_vm_types::AbortReason;

use crate::error::{DecodeError, InstantiateError};
use crate::interp::{ExecError, FuncAddr, ImportDispatch, Store, call, instantiate_module};
use crate::module::{CoreImportKind, RefModule, Ty};
use crate::ops::Value;

/// One import's dispatch: the boundary and the core arguments in, the
/// core results out.
type Dispatch<H> = fn(&mut Port<'_, H>, &[Value]) -> Result<Vec<Value>, MeterError>;

/// The interpreter's store, host and registers as the boundary.
struct Port<'a, H> {
    store: &'a mut Store,
    memory: usize,
    /// The counter's global index.
    fuel: u32,
    host: &'a mut H,
    registers: &'a mut Registers,
}

impl<H> Port<'_, H> {
    fn remaining(&self) -> u64 {
        self.store.global(self.fuel).as_i64().cast_unsigned()
    }

    fn set_remaining(&mut self, value: u64) {
        self.store
            .set_global(self.fuel, Value::I64(value.cast_signed()));
    }
}

impl<H: KernelHost> GuestMemory for Port<'_, H> {
    fn read(&self, ptr: u32, len: u32) -> Result<&[u8], MeterError> {
        self.store.memories[self.memory]
            .data
            .as_slice()
            .read(ptr, len)
    }

    fn write(&mut self, ptr: u32, bytes: &[u8]) -> Result<(), MeterError> {
        self.store.memories[self.memory]
            .data
            .as_mut_slice()
            .write(ptr, bytes)
    }
}

impl<H: KernelHost> HostAccess for Port<'_, H> {
    type Host = H;

    fn host(&mut self) -> &mut H {
        self.host
    }
}

impl<H: KernelHost> FuelSink for Port<'_, H> {
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted> {
        if let Some(left) = self.remaining().checked_sub(fuel) {
            self.set_remaining(left);
            Ok(())
        } else {
            // Zeroed as `exhaust` zeroes it, so the whole budget reads
            // as spent whichever way the counter ran out.
            self.set_remaining(0);
            Err(Exhausted)
        }
    }
}

impl<H: KernelHost> Boundary for Port<'_, H> {
    fn registers(&mut self) -> &mut Registers {
        self.registers
    }
}

/// A core argument as the `u32` every boundary parameter but a `u64` is.
fn u(args: &[Value], at: usize) -> u32 {
    args[at].as_i32().cast_unsigned()
}

/// One dispatch, over the argument positions it reads.
macro_rules! dispatch {
    ($f:ident($($i:literal),*) -> value) => {
        |port, args| abi::$f(port $(, u(args, $i))*).map(|v| vec![Value::I32(v.cast_signed())])
    };
    ($f:ident($($i:literal),*)) => {
        |port, args| abi::$f(port $(, u(args, $i))*).map(|()| Vec::new())
    };
}

/// The dispatch an import resolves to, by name.
fn resolve<H: KernelHost>(module: &str, name: &str) -> Option<Dispatch<H>> {
    use abi::{ABI, CRYPTO, ENV, EVENTS, MATH, STATE};
    Some(match (module, name) {
        (ABI, "arg") => dispatch!(arg(0, 1)),
        (ABI, "take") => dispatch!(take(0)),
        (ABI, "reply") => dispatch!(reply(0, 1)),
        (ABI, "answer") => dispatch!(answer(0, 1)),
        (STATE, "site-len") => dispatch!(site_len(0) -> value),
        (STATE, "site-declared") => dispatch!(site_declared(0, 1) -> value),
        (STATE, "site-get") => dispatch!(site_get(0, 1) -> value),
        (STATE, "site-set") => dispatch!(site_set(0, 1, 2, 3)),
        (STATE, "site-seal") => dispatch!(site_seal(0, 1)),
        (STATE, "site-open-seal") => dispatch!(site_open_seal(0, 1, 2) -> value),
        (STATE, "site-clear") => dispatch!(site_clear(0, 1)),
        (STATE, "site-balance") => dispatch!(site_balance(0, 1, 2)),
        (STATE, "site-take") => dispatch!(site_take(0, 1, 2) -> value),
        (STATE, "site-put") => dispatch!(site_put(0, 1, 2)),
        (STATE, "site-reserve-take") => dispatch!(site_reserve_take(0, 1) -> value),
        (STATE, "site-count") => dispatch!(site_count(0, 1) -> value),
        (STATE, "site-covered") => dispatch!(site_covered(0, 1) -> value),
        (STATE, "site-order") => dispatch!(site_order(0, 1, 2, 3)),
        (STATE, "site-entry") => dispatch!(site_entry(0, 1, 2) -> value),
        (STATE, "site-entry-set") => dispatch!(site_entry_set(0, 1, 2, 3, 4)),
        (STATE, "site-insert") => dispatch!(site_insert(0, 1, 2, 3, 4)),
        (STATE, "site-remove") => dispatch!(site_remove(0, 1, 2)),
        (STATE, "site-instance-take") => dispatch!(site_instance_take(0, 1, 2, 3) -> value),
        (STATE, "site-instance-put") => dispatch!(site_instance_put(0, 1, 2, 3, 4)),
        (STATE, "bucket-take") => dispatch!(bucket_take(0, 1) -> value),
        (STATE, "bucket-split") => dispatch!(bucket_split(0, 1, 2) -> value),
        (STATE, "bucket-put") => dispatch!(bucket_put(0, 1)),
        (STATE, "bucket-amount") => dispatch!(bucket_amount(0, 1)),
        (STATE, "bucket-drop") => dispatch!(bucket_drop(0)),
        (STATE, "mint") => dispatch!(mint(0, 1) -> value),
        (STATE, "mint-instances") => dispatch!(mint_instances(0, 1, 2) -> value),
        (STATE, "burn") => dispatch!(burn(0)),
        (MATH, "mul-div") => dispatch!(mul_div(0, 1, 2, 3, 4)),
        (MATH, "geometric-mean") => dispatch!(geometric_mean(0, 1, 2)),
        (MATH, "fraction-compose") => dispatch!(fraction_compose(0, 1, 2, 3, 4, 5)),
        (MATH, "fraction-cmp") => dispatch!(fraction_cmp(0, 1, 2, 3) -> value),
        (MATH, "fixed-pow") => dispatch!(fixed_pow(0, 1, 2, 3)),
        (ENV, "clock") => |port, _| Ok(vec![Value::I64(abi::clock(port).cast_signed())]),
        (CRYPTO, "hash") => dispatch!(hash(0, 1, 2)),
        (EVENTS, "emit") => dispatch!(emit(0, 1, 2)),
        _ => return None,
    })
}

/// The meter's `exhaust`: the counter is spent whole and the call is
/// refused out of gas.
fn exhaust<H: KernelHost>(
    port: &mut Port<'_, H>,
    _args: &[Value],
) -> Result<Vec<Value>, MeterError> {
    port.set_remaining(0);
    Err(MeterError::Exhausted)
}

/// The kernel behind a module's imports: the host, the registers, and
/// one dispatch per imported function in import order.
struct Kernel<H> {
    host: H,
    registers: Registers,
    memory: usize,
    fuel: u32,
    imports: Vec<Dispatch<H>>,
    params: Vec<usize>,
}

impl<H: KernelHost> ImportDispatch for Kernel<H> {
    fn param_count(&self, id: u32) -> usize {
        self.params[id as usize]
    }

    fn dispatch(
        &mut self,
        _modules: &[&RefModule],
        store: &mut Store,
        id: u32,
        args: Vec<Value>,
    ) -> Result<Vec<Value>, ExecError> {
        let mut port = Port {
            store,
            memory: self.memory,
            fuel: self.fuel,
            host: &mut self.host,
            registers: &mut self.registers,
        };
        (self.imports[id as usize])(&mut port, &args).map_err(fault)
    }
}

/// A metered failure as an interpreter error: both are the host's own
/// refusals, carrying their class.
const fn fault(error: MeterError) -> ExecError {
    match error {
        MeterError::Exhausted => ExecError::Host(AbortReason::OutOfGas),
        MeterError::Refused(reason) => ExecError::Host(reason),
    }
}

/// A module instance the kernel calls directly.
pub struct RefModuleInstance<'m, H> {
    module: &'m RefModule,
    store: Store,
    kernel: Kernel<H>,
    /// The whole budget, which the counter was set to less the prepaid
    /// instantiation.
    budget: u64,
}

impl<'m, H: KernelHost> RefModuleInstance<'m, H> {
    /// Instantiates `module` against `host`, bounded by `fuel`.
    ///
    /// Every import must be one the kernel defines, at the type it
    /// defines it, or the meter's `exhaust`; the module must export its
    /// memory as the kernel reads it and the counter as the meter
    /// defines it — what the validator and the pass produce, checked
    /// again here because the interpreter also runs modules that never
    /// faced them. Instantiation is prepaid off the counter: one per
    /// active data segment and one per byte, judged before any segment
    /// applies.
    ///
    /// # Errors
    ///
    /// The host comes back with the error, so a session survives a
    /// refused artifact: a decode error for an import or export outside
    /// the boundary, the budget failing to cover instantiation, or the
    /// trap instantiation produced.
    pub fn instantiate(
        module: &'m RefModule,
        host: H,
        fuel: u64,
    ) -> Result<Self, (H, InstantiateError)> {
        let mut imports = Vec::with_capacity(module.imports.entries.len());
        let mut params = Vec::with_capacity(module.imports.entries.len());
        for entry in &module.imports.entries {
            let CoreImportKind::Func(ty) = entry.kind else {
                let refused = DecodeError::Unsupported(format!(
                    "import `{}` `{}` is not a function",
                    entry.module, entry.name
                ));
                return Err((host, refused.into()));
            };
            let ty = &module.types[ty as usize];
            let (dispatch, declared_params, declared_results): (
                Dispatch<H>,
                &[CoreType],
                &[CoreType],
            ) = if entry.module == NAMESPACE && entry.name == EXHAUST {
                (exhaust, &[], &[])
            } else {
                let defined = IMPORTS
                    .iter()
                    .find(|(m, n, _, _)| *m == entry.module && *n == entry.name);
                let dispatch = resolve::<H>(&entry.module, &entry.name);
                let (Some((_, _, declared_params, declared_results)), Some(dispatch)) =
                    (defined, dispatch)
                else {
                    let refused = DecodeError::Unsupported(format!(
                        "import `{}` `{}` is not one the kernel defines",
                        entry.module, entry.name
                    ));
                    return Err((host, refused.into()));
                };
                (dispatch, declared_params, declared_results)
            };
            if !same(&ty.params, declared_params) || !same(&ty.results, declared_results) {
                let refused = DecodeError::Unsupported(format!(
                    "import `{}` `{}` is not at the type the kernel defines",
                    entry.module, entry.name
                ));
                return Err((host, refused.into()));
            }
            imports.push(dispatch);
            params.push(declared_params.len());
        }
        if !module.memory_exports.iter().any(|name| name == MEMORY) {
            let refused =
                DecodeError::Unsupported(format!("the module exports no memory `{MEMORY}`"));
            return Err((host, refused.into()));
        }
        let Some(fuel_index) = module.global_exports.get(FUEL).copied() else {
            let refused = DecodeError::Unsupported(format!(
                "the module exports no counter `{FUEL}`: it was not admitted through the meter"
            ));
            return Err((host, refused.into()));
        };
        // One per active data segment plus one per byte, the other
        // statement of the charge the meter derives from the bytes.
        let prepaid = module.datas.iter().fold(0u64, |cost, seg| {
            cost.saturating_add(1 + seg.items.len() as u64)
        });
        let Some(left) = fuel.checked_sub(prepaid) else {
            return Err((host, InstantiateError::OutOfGas));
        };
        let mut store = Store::default();
        let imported: Vec<FuncAddr> = (0..imports.len())
            .map(|id| FuncAddr::Import(u32::try_from(id).unwrap_or(u32::MAX)))
            .collect();
        if let Err(trap) = instantiate_module(&[module], &mut store, 0, imported, None, None) {
            return Err((host, InstantiateError::Trap(trap)));
        }
        let Some(memory) = store.instances[0].memory else {
            let refused = DecodeError::Unsupported("the module declares no memory".to_owned());
            return Err((host, refused.into()));
        };
        let memory = memory as usize;
        store.set_global(fuel_index, Value::I64(left.cast_signed()));
        Ok(Self {
            module,
            store,
            kernel: Kernel {
                host,
                registers: Registers::default(),
                memory,
                fuel: fuel_index,
                imports,
                params,
            },
            budget: fuel,
        })
    }

    /// Invokes `export` with `args`, folding how it ended into the
    /// protocol's vocabulary: the verdict, and the fuel consumed since
    /// instantiation.
    ///
    /// Infallible on the same terms as the blessed engine's invocation:
    /// every ending is a verdict.
    pub fn invoke(&mut self, export: &str, args: &[GuestArg<'_>]) -> Invocation {
        let result = self.call(export, args);
        Invocation {
            result,
            fuel: self.consumed(),
        }
    }

    fn call(&mut self, export: &str, args: &[GuestArg<'_>]) -> Invoked {
        let Some(&index) = self.module.exports.get(export) else {
            return Invoked::Aborted(AbortReason::ExportMissing);
        };
        let Ok((values, registers)) = abi::lower(args) else {
            return Invoked::Aborted(AbortReason::AbiViolation);
        };
        let ty = self.module.func_type(index);
        let values: Vec<Value> = values
            .into_iter()
            .map(|value| match value {
                CoreValue::I32(bits) => Value::I32(bits.cast_signed()),
                CoreValue::I64(bits) => Value::I64(bits.cast_signed()),
            })
            .collect();
        let typed = values.len() == ty.params.len()
            && values.iter().zip(&ty.params).all(|(value, want)| {
                matches!(
                    (value, want),
                    (Value::I32(_), Ty::I32) | (Value::I64(_), Ty::I64)
                )
            });
        if !typed {
            return Invoked::Aborted(AbortReason::AbiViolation);
        }
        self.kernel.registers = registers;
        self.store.depth = 0;
        let addr = FuncAddr::Wasm {
            instance: 0,
            func: index,
        };
        let returned = call(
            &[self.module],
            &mut self.kernel,
            &mut self.store,
            addr,
            values,
        );
        match returned {
            Ok(values) => match values.first() {
                None | Some(Value::I32(0)) => match self.kernel.registers.reply() {
                    Some(reply) => Invoked::Produced {
                        edges: reply.edges,
                        answer: reply.answer,
                    },
                    None => Invoked::Aborted(AbortReason::BadReturnShape),
                },
                Some(Value::I32(code)) => Invoked::Declined(code.cast_unsigned() - 1),
                Some(Value::I64(_)) => Invoked::Aborted(AbortReason::BadReturnShape),
            },
            Err(ExecError::Trap(trap)) => Invoked::Aborted(trap.abort_reason()),
            Err(ExecError::Host(reason)) => Invoked::Aborted(reason),
            Err(ExecError::Internal(_)) => Invoked::Aborted(AbortReason::AbiViolation),
        }
    }

    /// Fuel consumed of the budget: the prepaid instantiation and every
    /// call since, read off the counter.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        let remaining = self.store.global(self.kernel.fuel).as_i64().cast_unsigned();
        self.budget.saturating_sub(remaining)
    }

    /// The host, once the instance is done with.
    pub fn into_host(self) -> H {
        self.kernel.host
    }
}

/// Whether a declared type list is the boundary's.
fn same(declared: &[Ty], defined: &[CoreType]) -> bool {
    declared.len() == defined.len()
        && declared
            .iter()
            .zip(defined)
            .all(|(d, e)| matches!((d, e), (Ty::I32, CoreType::I32) | (Ty::I64, CoreType::I64)))
}
