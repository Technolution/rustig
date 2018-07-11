// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

fn invoke_clos(func: Box<Fn() -> ()>) {
    func();
}

fn main() {
    let message = "Hello world!";
    let func = move || println!("{}", message);
    invoke_clos(Box::new(func));
}
