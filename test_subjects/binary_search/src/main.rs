// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::Ordering::*;
#[inline(never)]
pub fn binary_search<T: Ord>(arr: &[T], elem: &T) -> Option<usize> {
    let mut size = arr.len();
    let mut base = 0;

    while size > 0 {
        size /= 2;
        let mid = base + size;

        base = match arr[mid].cmp(elem) {
            Less => mid + 1,
            Greater => base,
            Equal => return Some(mid),
        };
    }
    None
}

fn main() {
    binary_search(&[1, 2, 3], &2);
}
