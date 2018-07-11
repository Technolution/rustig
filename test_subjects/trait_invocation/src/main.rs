// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct Foo;

trait Baz {
    fn m5(&self);
    fn m6(&self);
}

impl Baz for Foo {
    fn m5(&self) {
        println!("Hello! m5");
    }
    fn m6(&self) {
        println!("Hello! m6");
    }
}

fn qux<T: Baz + ?Sized>(x: &T) {
    x.m5();
    x.m6();
}

fn main() {
    let x: &Baz = &Foo;
    qux(x);
}
