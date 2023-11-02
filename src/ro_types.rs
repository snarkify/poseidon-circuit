use crate::main_gate::RegionCtx;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::circuit::AssignedCell;
use halo2_proofs::plonk::Error;

/// A helper trait that defines the constants associated with a hash function
pub trait ROConstantsTrait {
    /// produces constants/parameters associated with the hash function
    fn new(r_f: usize, r_p: usize) -> Self;
}
pub trait ROTrait<C: CurveAffine> {
    /// A type representing constants/parameters associated with the hash function
    type Constants: ROConstantsTrait;

    /// Initializes the hash function
    fn new(constants: Self::Constants) -> Self;

    /// Returns a challenge by hashing the internal state
    fn squeeze(&mut self) -> C::Scalar;
}

/// A helper trait that defines the behavior of a hash function that we use as an RO in the circuit model
pub trait ROCircuitTrait<C: CurveAffine> {
    /// A type representing constants/parameters associated with the hash function
    type Constants: ROConstantsTrait;

    /// Initializes the hash function
    fn new(constants: Self::Constants) -> Self;

    fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
    ) -> Result<Vec<AssignedCell<C::Scalar, C::Scalar>>, Error>;
}
