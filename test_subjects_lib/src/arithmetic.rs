// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[inline(never)]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[inline(never)]
pub fn subtract(a: i32, b: i32) -> i32 {
    a - b
}

#[inline(never)]
pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

#[inline(never)]
pub fn divide(a: i32, b: i32) -> i32 {
    a / b
}

#[inline(never)]
pub fn divide_no_overflow(a: i32, b: i32) -> Option<i32> {
    // If opt-level >= 1, this optimizes away the divide by zero overflow check
    if a == <i32>::min_value() {
        None
    } else {
        Some (a / b)
    }
}

#[inline(never)]
pub fn divide_safe(a: i32, b: i32) -> Option<i32> {
    // If opt-level >= 1, this optimizes away the divide by zero overflow check
    if a == <i32>::min_value() || b == 0 {
        None
    } else {
        Some (a / b)
    }
}

#[inline(never)]
pub fn remainder(a: i32, b: i32) -> i32 {
    a % b
}

#[inline(never)]
pub fn remainder_no_overflow(a: i32, b: i32) -> Option<i32> {
    // If opt-level >= 1, this optimizes away the divide by zero overflow check
    if a == <i32>::min_value() {
        None
    } else {
        Some (a % b)
    }
}

#[inline(never)]
pub fn remainder_safe(a: i32, b: i32) -> Option<i32> {
    // If opt-level >= 1, this optimizes away the divide by zero overflow check
    if a == <i32>::min_value() || b == 0{
        None
    } else {
        Some (a % b)
    }
}

#[inline(never)]
pub fn shl(a: i32, b: i32) -> i32 {
    a << b
}

#[inline(never)]
pub fn shr(a: i32, b: i32) -> i32 {
    a >> b
}

#[inline(never)]
pub fn equal(a: i32, b: i32) {
    assert_eq!(a, b);
}