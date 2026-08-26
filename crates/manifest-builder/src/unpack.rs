//! The affine unpack a bundle of handles shares.
//!
//! A call's produced edges and an intent's open sockets both come back
//! as a vector whose arity the declaration answers rather than the
//! consuming site, and both are consumed by claiming it: destructure
//! into an array, take the single item, keep the vector, or discharge
//! an empty bundle. A wrong claim refuses with the bundle's own
//! provenance, which is what [`Arity`] folds in.

/// How a bundle refuses an arity claim: with its own provenance folded
/// into its own tier's error.
pub trait Arity {
    /// The refusing tier's error type.
    type Error;

    /// The refusal for claiming `claimed` items of a bundle holding
    /// `declared`.
    fn refuse(self, declared: usize, claimed: usize) -> Self::Error;
}

/// A bundle of affine handles, unpacked by asserting its arity.
#[derive(Debug)]
#[must_use = "every handle in the bundle must be consumed for its build to pass"]
pub struct Unpacked<T, C> {
    pub(crate) context: C,
    pub(crate) items: Vec<T>,
}

impl<T, C: Arity> Unpacked<T, C> {
    /// How many handles the bundle holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the bundle holds none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Unpack into an array, most often by destructuring — `let [first,
    /// second] = ….into_array()?` — which is where `N` comes from.
    ///
    /// # Errors
    ///
    /// The bundle's arity refusal, when the declaration answers some
    /// other number.
    pub fn into_array<const N: usize>(self) -> Result<[T; N], C::Error> {
        let Self { context, items } = self;
        let declared = items.len();
        items.try_into().map_err(|_| context.refuse(declared, N))
    }

    /// The single handle of a bundle holding one.
    ///
    /// # Errors
    ///
    /// The bundle's arity refusal, when the declaration answers some
    /// other number.
    pub fn one(self) -> Result<T, C::Error> {
        let [item] = self.into_array()?;
        Ok(item)
    }

    /// Every handle, in declaration order.
    ///
    /// What a consumer wants where the count is the declaration's answer
    /// rather than a number the consuming site knows.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }

    /// Discharge a bundle that holds nothing.
    ///
    /// # Errors
    ///
    /// The bundle's arity refusal, when the declaration answers a handle
    /// that would then dangle.
    pub fn none(self) -> Result<(), C::Error> {
        let [] = self.into_array()?;
        Ok(())
    }
}
