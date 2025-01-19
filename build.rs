use rand::Rng;
fn main() {
    // compile hook
    cc::Build::new().file("hook.asm").compile("hook");

    //randomise obfstr seed
    let random_str = get_random_string(32);
    println!("cargo:rustc-env=OBFSTR_SEED={}", random_str);
}

fn get_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut string = String::new();
    for _ in 0..length {
        let character: char = rng.gen_range(0x21..0x7E).into();
        string.push(character);
    }
    string
}
