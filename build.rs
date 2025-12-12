fn main() {
    // Point SQLx macros at the local SQLite file for compile-time verification.
    println!("cargo:rustc-env=DATABASE_URL=sqlite://pubkeys.db");
    println!("cargo:rerun-if-changed=pubkeys.db");
    println!("cargo:rerun-if-changed=build.rs");
}
