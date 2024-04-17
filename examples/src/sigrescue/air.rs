use super::{SIGN_LENGTH, TRACE_WIDTH};
use crate::utils::rescue::{self, CYCLE_LENGTH};
use crate::utils::{are_equal, is_zero, not, EvaluationResult};
use winterfell::math::ToElements;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// Ring Signature AIR
// ================================================================================================

#[derive(Clone)]
pub struct PublicInputs {
    pub pub_key_root: [BaseElement; 2],
    pub num_pub_keys: usize,
    pub tag: [BaseElement; 2],
    pub eventid: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = self.pub_key_root.to_vec();
        result.push(BaseElement::from(self.num_pub_keys as u64));
        result.extend_from_slice(&self.tag);
        result
    }
}

pub struct RingSigAir {
    context: AirContext<BaseElement>,
    pub_key_root: [BaseElement; 2],
    num_pub_keys: usize,
    tag: [BaseElement; 2],
    eventid: BaseElement,
}

impl Air for RingSigAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    #[rustfmt::skip]
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        
        // transition constraint degrees defines the total number of transition constraints and their expected degrees
        let degrees = vec![
            // rescue alpha is 5
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        RingSigAir {
            context: AirContext::new(trace_info, degrees, 5, options),
            pub_key_root: pub_inputs.pub_key_root,
            num_pub_keys: pub_inputs.num_pub_keys,

            tag: pub_inputs.tag,
            eventid:pub_inputs.eventid,
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        //assertion requires that the value in the specified `column` at the specified `step` is equal to the provided `value`.
        let num_cycles = self.num_pub_keys.next_power_of_two();
        let idx_length = (num_cycles as f32).log2() as usize;
        let tag_pos = CYCLE_LENGTH - 1;
        let last_step = SIGN_LENGTH + idx_length * CYCLE_LENGTH - 1;

        let assertions = vec![
            // assert the input is the signing message
            Assertion::single(2, tag_pos, self.tag[0]),
            Assertion::single(3, tag_pos, self.tag[1]),
            Assertion::single(3, 0, self.eventid),
            Assertion::single(2, last_step, self.pub_key_root[0]),
            Assertion::single(3, last_step, self.pub_key_root[1]),
        ];
        assertions
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // expected state width is 4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // spit periodic values into flags and Rescue round constants
        let tag_flag = periodic_values[0];
        let hash_flag = periodic_values[1];
        let ark = &periodic_values[2..];

        rescue::enforce_round(result, &current[2..], &next[2..], ark, hash_flag);

        let hash_init_flag = not(hash_flag);
        result.agg_constraint(
            0,
            hash_init_flag,
            (tag_flag - E::ONE)
                * (next[0] - E::ONE)
                * are_equal(current[2], next[2])
                * are_equal(current[3], next[3]),
        );

        result.agg_constraint(
            1,
            hash_init_flag,
            (tag_flag - E::ONE)
                * (next[0])
                * are_equal(current[2], next[4])
                * are_equal(current[3], next[5]),
        );

        result.agg_constraint(2, hash_init_flag, tag_flag * are_equal(current[1], next[2]));

        result.agg_constraint(3, hash_flag, are_equal(current[1], next[1]));

        let value = next[0] * (next[0] - E::ONE);
        result.agg_constraint(4, hash_init_flag, is_zero(value));

        result.agg_constraint(5, hash_flag, tag_flag * are_equal(current[1], current[2]));
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![];
        let num_cycles = self.num_pub_keys.next_power_of_two();
        let idx_length = (num_cycles as f32).log2() as usize;
        let last_step = SIGN_LENGTH + idx_length * CYCLE_LENGTH;

        let padding_length = last_step.next_power_of_two();
        let mut counter = vec![BaseElement::ZERO; padding_length];
        counter[0] = BaseElement::ONE;
        counter[CYCLE_LENGTH - 1] = BaseElement::ONE;
        result.push(counter);

        result.push(HASH_CYCLE_MASK.to_vec());
        result.append(&mut rescue::get_round_constants());
        result
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

const HASH_CYCLE_MASK: [BaseElement; CYCLE_LENGTH] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];
