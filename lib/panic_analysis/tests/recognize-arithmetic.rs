// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(test)]
mod test {
    extern crate panic_analysis;
    extern crate test_common;

    use self::panic_analysis::PanicPattern::Arithmetic;
    use self::panic_analysis::*;
    use self::test_common::TestSubjectType::*;
    use self::test_common::*;

    /// helper method that checks if a trace through function `function_name`, exists in the test subject "arithmetic" on type `subject_type`.
    /// It is asserted that the trace has `expected_message` as message as well.
    fn assert_trace_present(
        function_name: &str,
        expected_message: &str,
        subject_type: &TestSubjectType,
    ) {
        let path = test_common::get_test_subject_path("arithmetic", subject_type);
        let binary_path = path.to_str().map(|x| x.to_string());
        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();

        let target_trace = calls
            .calls
            .iter()
            .find(|trace| {
                trace.backtrace[1].procedure.borrow().linkage_name_demangled == function_name
            })
            .unwrap_or_else(|| panic!("No trace through function '{}' found", function_name));

        assert_eq!(*target_trace.pattern.borrow(), Arithmetic);
        assert_eq!(target_trace.message, Some(expected_message.to_string()));
    }

    // Test if an overflow check on a `+` operator is detected with the correct message.
    #[test]
    fn test_add() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::add",
            "attempt to add with overflow",
            &Debug,
        );
    }

    // Test if an overflow check on a `-` operator is detected with the correct message.
    #[test]
    fn test_subtract() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::subtract",
            "attempt to subtract with overflow",
            &Debug,
        );
    }

    // Test if an overflow check on a `*` operator is detected with the correct message.
    #[test]
    fn test_multiply() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::multiply",
            "attempt to multiply with overflow",
            &Debug,
        );
    }

    // Test if an overflow check on a `<<` operator is detected with the correct message.
    #[test]
    fn test_shift_left() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::shl",
            "attempt to shift left with overflow",
            &Debug,
        );
    }

    // Test if an overflow check on a `>>` operator is detected with the correct message.
    #[test]
    fn test_shift_right() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::shr",
            "attempt to shift right with overflow",
            &Debug,
        );
    }

    // Test if an overflow check on a `/` operator is detected with the correct message.
    #[test]
    fn test_divide_overflow() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::divide",
            "attempt to divide with overflow",
            &Release,
        );
    }

    // Test if an overflow check on a `%` operator is detected with the correct message.
    #[test]
    fn test_remainder_overflow() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::remainder",
            "attempt to calculate the remainder with overflow",
            &Release,
        );
    }

    // Test if an divide by 0 check on a `/` operator is detected with the correct message.
    // This does only occur if the overflow check is optimized away
    #[test]
    fn test_divide_zero() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::divide_no_overflow",
            "attempt to divide by zero",
            &Release,
        );
    }

    // Test if an divide by 0 check on a `%` operator is detected with the correct message.
    // This does only occur if the overflow check is optimized away
    #[test]
    fn test_remainder_zero() {
        assert_trace_present(
            "test_subjects_lib::arithmetic::remainder_no_overflow",
            "attempt to calculate the remainder with a divisor of zero",
            &Release,
        );
    }
}
