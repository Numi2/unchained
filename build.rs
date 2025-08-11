fn main() {
    // When linking against an external LLRS library, allow users to specify the
    // library search directory via LLRS_LIB_DIR. We only emit link flags when
    // the llrs_ffi feature is enabled to avoid accidental linkage.
    if std::env::var("CARGO_FEATURE_LLRS_FFI").is_ok() {
        if let Ok(dir) = std::env::var("LLRS_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", dir);
        }
        // Default library name is 'llrs'. Override via LLRS_LIB_NAME if needed.
        let lib_name = std::env::var("LLRS_LIB_NAME").unwrap_or_else(|_| "llrs".to_string());
        println!("cargo:rustc-link-lib={}\n", lib_name);
    }
}


