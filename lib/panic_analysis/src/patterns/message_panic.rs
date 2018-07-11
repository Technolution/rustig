// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph::Context;
use patterns::PatternFinder;
use std::collections::HashMap;
use AnalysisOptions;
use PanicCallsCollection;
use PanicPattern;
use PanicPattern::Arithmetic;

/// Implementation of the `PatternFinder` to categorize panic traces based on messages
struct MessagePatternFinder<'a> {
    // A hashmap that maps a message to the pattern the trace should be recognized as.
    message_pattern_mapping: HashMap<&'a str, PanicPattern>,
}

impl<'a> PatternFinder for MessagePatternFinder<'a> {
    fn find_patterns(&self, _ctx: &Context, panic_calls: &PanicCallsCollection) {
        panic_calls
            .calls
            .iter()
            .filter(|panic_trace| panic_trace.message.is_some())
            .for_each(|panic_trace| {
                self.message_pattern_mapping
                    .get(panic_trace.message.as_ref().unwrap().as_str())
                    .map(|pattern| panic_trace.pattern.replace(*pattern));
            })
    }
}

pub fn get_messages_pattern_finder(_options: &AnalysisOptions) -> Box<PatternFinder> {
    let mut messages_map = HashMap::new();
    messages_map.insert("attempt to add with overflow", Arithmetic);
    messages_map.insert("attempt to subtract with overflow", Arithmetic);
    messages_map.insert("attempt to multiply with overflow", Arithmetic);

    messages_map.insert("attempt to divide with overflow", Arithmetic);
    messages_map.insert(
        "attempt to calculate the remainder with overflow",
        Arithmetic,
    );
    messages_map.insert("attempt to divide by zero", Arithmetic);
    messages_map.insert(
        "attempt to calculate the remainder with a divisor of zero",
        Arithmetic,
    );

    messages_map.insert("attempt to shift left with overflow", Arithmetic);
    messages_map.insert("attempt to shift right with overflow", Arithmetic);

    Box::new(MessagePatternFinder {
        message_pattern_mapping: messages_map,
    })
}

#[cfg(test)]
mod test {
    extern crate test_common;

    use self::test_common::*;
    use super::*;

    use PanicCall;
    use PanicPattern::Indexing;
    use PanicPattern::Unrecognized;

    use std::cell::RefCell;

    use test_utils::*;

    /// Test if a `PanicCall` is marked correctly if its message is in `message_pattern_mapping`.
    #[test]
    pub fn test_recognized_correctly_first_entry_first_index() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: Vec::new(),
                pattern: RefCell::new(Unrecognized),
                contains_dynamic_invocation: false,
                message: Some("arith".to_string()),
            }],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[0].pattern.borrow(), Arithmetic);
    }

    /// Test if a `PanicCall` is marked correctly if its message is in `message_pattern_mapping`.
    #[test]
    pub fn test_recognized_correctly_first_entry_last_index() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: Vec::new(),
                pattern: RefCell::new(Unrecognized),
                contains_dynamic_invocation: false,
                message: Some("index".to_string()),
            }],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[0].pattern.borrow(), Indexing);
    }

    /// Test if multiple `PanicCall`s are marked correctly if their messages are in `message_pattern_mapping`.
    #[test]
    pub fn test_recognized_correctly_multiple() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: Some("index".to_string()),
                },
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: Some("arith".to_string()),
                },
            ],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[0].pattern.borrow(), Indexing);
        assert_eq!(*panic_collection.calls[1].pattern.borrow(), Arithmetic);
    }

    /// Test if a `PanicCall`s is marked correctly if it is further in the trace.
    #[test]
    pub fn test_recognized_correctly_last_entry_last_index() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: None,
                },
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: None,
                },
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: None,
                },
                PanicCall {
                    backtrace: Vec::new(),
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation: false,
                    message: Some("index".to_string()),
                },
            ],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[3].pattern.borrow(), Indexing);
    }

    /// Test if a `PanicCall` is not marked when its message is not in `message_pattern_mapping`.
    #[test]
    pub fn test_not_recognized_no_matching_message() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: Vec::new(),
                pattern: RefCell::new(Unrecognized),
                contains_dynamic_invocation: false,
                message: Some("not present".to_string()),
            }],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[0].pattern.borrow(), Unrecognized);
    }

    /// Test if a `PanicCall` is not marked when its message is `None`.
    #[test]
    pub fn test_not_recognized_message_none() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let mut message_pattern_mapping = HashMap::new();
        message_pattern_mapping.insert("arith", Arithmetic);
        message_pattern_mapping.insert("index", Indexing);

        let finder = MessagePatternFinder {
            message_pattern_mapping,
        };

        let panic_collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: Vec::new(),
                pattern: RefCell::new(Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        finder.find_patterns(&context, &panic_collection);

        assert_eq!(*panic_collection.calls[0].pattern.borrow(), Unrecognized);
    }
}
