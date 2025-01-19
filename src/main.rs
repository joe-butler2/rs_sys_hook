#![windows_subsystem = "console"]
#![allow(unused_variables)]

mod dynimp;
mod hook;
mod structs;

use hook::hook_query_information;

fn main() {
    hook_query_information();
    loop {}
}
