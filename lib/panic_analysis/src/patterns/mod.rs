// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod direct_panic;
mod function_panic;
mod message_panic;

use callgraph::Context;
use AnalysisOptions;
use PanicCallsCollection;

use patterns::direct_panic::get_direct_panic_pattern_finder;
use patterns::function_panic::get_function_names_pattern_finder;
use patterns::message_panic::get_messages_pattern_finder;

/// Trait marking structs that can recognize common patterns in a panic call
pub trait PatternFinder {
    fn find_patterns(&self, ctx: &Context, panic_calls: &PanicCallsCollection);
}

/// Combination of multiple `PatternFinder` implementations.
struct CombinedPatternFinder {
    finders: Vec<Box<PatternFinder>>,
}

impl PatternFinder for CombinedPatternFinder {
    fn find_patterns(&self, ctx: &Context, panic_calls: &PanicCallsCollection) {
        self.finders
            .iter()
            .for_each(|finder| finder.find_patterns(ctx, panic_calls))
    }
}

pub fn get_pattern_finder(options: &AnalysisOptions) -> Box<PatternFinder> {
    let direct_panic_finder = get_direct_panic_pattern_finder(options);
    let unwrap_panic_finder = get_function_names_pattern_finder(options);
    let message_panic_finder = get_messages_pattern_finder(options);

    Box::new(CombinedPatternFinder {
        finders: vec![
            direct_panic_finder,
            unwrap_panic_finder,
            message_panic_finder,
        ],
    })
}

#[cfg(test)]
mod test {
    extern crate callgraph;
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate std;
    extern crate test_common;

    use super::*;

    use std::cell::Cell;
    use std::rc::Rc;

    use test_utils;

    struct FakePatternFinder {
        called: Rc<Cell<bool>>,
    }

    impl PatternFinder for FakePatternFinder {
        fn find_patterns(&self, _context: &Context, _panic_calls: &PanicCallsCollection) {
            self.called.replace(true);
        }
    }

    /// Verify that `CombinedPatternFinder` calls all it's children when .`find_patterns` is executed
    #[test]
    fn test_markers_calls() {
        let cell1 = Rc::new(Cell::new(false));
        let cell1_rc = cell1.clone();
        let marker1 = Box::new(FakePatternFinder { called: cell1 });

        let cell2 = Rc::new(Cell::new(false));
        let cell2_rc = cell2.clone();
        let marker2 = Box::new(FakePatternFinder { called: cell2 });

        let finders: Vec<Box<PatternFinder>> = vec![marker1, marker2];
        let all_finders = CombinedPatternFinder { finders };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        let collection = PanicCallsCollection { calls: Vec::new() };
        all_finders.find_patterns(&context, &collection);

        assert!(cell1_rc.get());
        assert!(cell2_rc.get());
    }
}
