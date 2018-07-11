// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::any::Any;
use std::thread;

fn main() -> Result<(), Box<Any + Send + 'static>> {
    let handle1 = thread::spawn(|| {
        println!("Hello from thread 1");
        panic!("Panic in thread 1");
    });

    let handle2 = thread::spawn(|| {
        println!("Hello from thread 2");
        panic!("Panic in thread 2");
    });

    handle1.join()?;
    handle2.join()?
}
