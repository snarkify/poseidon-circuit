use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};

pub type AssignedValue<F> = AssignedCell<F, F>;

#[derive(Debug)]
pub struct RegionCtx<'a, F: PrimeField> {
    pub region: Region<'a, F>,
    pub offset: usize,
}

impl<'a, F: PrimeField> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>, offset: usize) -> Self {
        RegionCtx { region, offset }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn into_region(self) -> Region<'a, F> {
        self.region
    }

    pub fn assign_fixed<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedValue<F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_fixed(annotation, column, self.offset, || Value::known(value))
    }

    pub fn assign_advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedValue<F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice(annotation, column, self.offset, || value)
    }

    pub fn constrain_equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn next(&mut self) {
        self.offset += 1
    }
}

#[derive(Clone, Debug)]
pub enum WrapValue<F: PrimeField> {
    Assigned(AssignedValue<F>),
    Unassigned(Value<F>),
    Zero,
}

impl<F: PrimeField> From<Value<F>> for WrapValue<F> {
    fn from(val: Value<F>) -> Self {
        WrapValue::Unassigned(val)
    }
}

impl<F: PrimeField> From<AssignedValue<F>> for WrapValue<F> {
    fn from(val: AssignedValue<F>) -> Self {
        WrapValue::Assigned(val)
    }
}

impl<F: PrimeField> From<&AssignedValue<F>> for WrapValue<F> {
    fn from(val: &AssignedValue<F>) -> Self {
        WrapValue::Assigned(val.clone())
    }
}

#[derive(Clone, Debug)]
pub struct MainGateConfig<const T: usize> {
    pub(crate) state: [Column<Advice>; T],
    pub(crate) input: Column<Advice>,
    pub(crate) out: Column<Advice>,
    pub(crate) q_m: Column<Fixed>,
    // for linear term
    pub(crate) q_1: [Column<Fixed>; T],
    // for quintic term
    pub(crate) q_5: [Column<Fixed>; T],
    pub(crate) q_i: Column<Fixed>,
    pub(crate) q_o: Column<Fixed>,
    pub(crate) rc: Column<Fixed>,
}

#[derive(Debug)]
pub struct MainGate<F: PrimeField, const T: usize> {
    config: MainGateConfig<T>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField, const T: usize> Chip<F> for MainGate<F, T> {
    type Config = MainGateConfig<T>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: PrimeField, const T: usize> MainGate<F, T> {
    pub fn new(config: MainGateConfig<T>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        adv_cols: &mut (impl Iterator<Item = Column<Advice>> + Clone),
        fix_cols: &mut (impl Iterator<Item = Column<Fixed>> + Clone),
    ) -> MainGateConfig<T> {
        assert!(T >= 2);
        let state = [0; T].map(|_| adv_cols.next().unwrap());
        let input = adv_cols.next().unwrap();
        let out = adv_cols.next().unwrap();
        let q_1 = [0; T].map(|_| fix_cols.next().unwrap());
        let q_5 = [0; T].map(|_| fix_cols.next().unwrap());
        let q_m = fix_cols.next().unwrap();
        let q_i = fix_cols.next().unwrap();
        let q_o = fix_cols.next().unwrap();
        let rc = fix_cols.next().unwrap();

        state.map(|s| {
            meta.enable_equality(s);
        });
        meta.enable_equality(input);
        meta.enable_equality(out);

        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("q_m*s[0]*s[1] + sum_i(q_1[i]*s[i]) + sum_i(q_5[i]*s[i]^5) + rc + q_i*input + q_o*out=0", |meta|{
            let state = state.into_iter().map(|s| meta.query_advice(s, Rotation::cur())).collect::<Vec<_>>();
            let input = meta.query_advice(input, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            let q_1 = q_1.into_iter().map(|q| meta.query_fixed(q, Rotation::cur())).collect::<Vec<_>>();
            let q_5 = q_5.into_iter().map(|q| meta.query_fixed(q, Rotation::cur())).collect::<Vec<_>>();
            let q_m = meta.query_fixed(q_m, Rotation::cur());
            let q_i = meta.query_fixed(q_i, Rotation::cur());
            let q_o = meta.query_fixed(q_o, Rotation::cur());
            let rc = meta.query_fixed(rc, Rotation::cur());
            let init_term = q_m * state[0].clone() * state[1].clone() + q_i * input + rc + q_o * out;
            let res = state.into_iter().zip(q_1).zip(q_5).map(|((s, q1), q5)| {
                q1 * s.clone()  +  q5 * pow_5(s)
            }).fold(init_term, |acc, item| {
                acc + item
            });
            vec![res]
        });

        MainGateConfig {
            state,
            input,
            out,
            q_m,
            q_1,
            q_5,
            q_i,
            q_o,
            rc,
        }
    }

    // helper function for some usecases: no copy constraints, only return out cell
    // state: (q_1, q_m, state), out: (q_o, out)
    #[allow(clippy::type_complexity)]
    pub fn apply(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: (Option<Vec<F>>, Option<F>, Option<Vec<WrapValue<F>>>),
        rc: Option<F>,
        out: (F, WrapValue<F>),
    ) -> Result<AssignedValue<F>, Error> {
        if let Some(q_1) = state.0 {
            for (i, val) in q_1.iter().enumerate() {
                ctx.assign_fixed(|| "q_1", self.config.q_1[i], *val)?;
            }
        }
        if let Some(q_m_val) = state.1 {
            ctx.assign_fixed(|| "q_m", self.config.q_m, q_m_val)?;
        }
        if let Some(state) = state.2 {
            for (i, val) in state.iter().enumerate() {
                match val {
                    WrapValue::Unassigned(vv) => {
                        ctx.assign_advice(|| "state", self.config.state[i], *vv)?;
                    }
                    WrapValue::Assigned(avv) => {
                        let si = ctx.assign_advice(
                            || "state",
                            self.config.state[i],
                            avv.value().copied(),
                        )?;
                        ctx.constrain_equal(si.cell(), avv.cell())?;
                    }
                    _ => {}
                }
            }
        }

        if let Some(rc_val) = rc {
            ctx.assign_fixed(|| "rc", self.config.rc, rc_val)?;
        }

        ctx.assign_fixed(|| "q_o", self.config.q_o, out.0)?;

        let res = match out.1 {
            WrapValue::Unassigned(vv) => ctx.assign_advice(|| "out", self.config.out, vv)?,
            WrapValue::Assigned(avv) => {
                let out = ctx.assign_advice(|| "out", self.config.out, avv.value().copied())?;
                ctx.constrain_equal(out.cell(), avv.cell())?;
                out
            }
            WrapValue::Zero => {
                unimplemented!() // this is not allowed
            }
        };
        ctx.next();
        Ok(res)
    }
}
