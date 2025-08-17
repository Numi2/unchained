// oqs_dili_seeded.rs
// Helper binary: Deterministic ML-DSA-65 keygen via liboqs using a BLAKE3 XOF RNG.
// Reads exactly 32 bytes seed from stdin, outputs raw pk||sk to stdout and exits.

use std::io::{Read, Write};
use once_cell::sync::OnceCell;
use std::sync::Mutex;
use zeroize::Zeroize;
#[cfg(feature = "liboqs")]
use oqs_sys::rand::OQS_randombytes_custom_algorithm;

struct XofState {
    seed: [u8; 32],
    xof: blake3::OutputReader,
}

impl XofState {
    fn new(seed: [u8; 32]) -> Self {
        let mut h = blake3::Hasher::new_keyed(&seed);
        h.update(b"unchained-oqs-rng-xof-v1");
        let xof = h.finalize_xof();
        Self { seed, xof }
    }
}

impl Drop for XofState {
    fn drop(&mut self) {
        self.seed.zeroize();
        // OutputReader cannot be zeroized; it is ephemeral and dropped here.
    }
}

static DET_RNG: OnceCell<Mutex<Option<XofState>>> = OnceCell::new();

#[cfg(feature = "liboqs")]
unsafe extern "C" fn oqs_custom_randombytes(out_ptr: *mut u8, out_len: usize) {
    let slice = std::slice::from_raw_parts_mut(out_ptr, out_len);
    if let Some(cell) = DET_RNG.get() {
        if let Ok(mut guard) = cell.lock() {
            if let Some(state) = guard.as_mut() {
                state.xof.fill(slice);
                return;
            }
        }
    }
    panic!("deterministic RNG state not initialized");
}

fn main() {
    // Read exactly 32 bytes seed from stdin
    let mut seed = [0u8; 32];
    let mut read_total = 0usize;
    while read_total < 32 {
        match std::io::stdin().read(&mut seed[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(_) => break,
        }
    }
    if read_total != 32 {
        eprintln!("expected 32 bytes of seed on stdin, got {}", read_total);
        std::process::exit(2);
    }

    // Initialize oqs and set RNG
    #[cfg(feature = "liboqs")]
    oqs::init();
    let cell = DET_RNG.get_or_init(|| Mutex::new(None));
    {
        let mut guard = cell.lock().expect("rng mutex poisoned");
        *guard = Some(XofState::new(seed));
    }
    #[cfg(feature = "liboqs")]
    unsafe { OQS_randombytes_custom_algorithm(Some(oqs_custom_randombytes)); }

    // Generate ML-DSA-65 keypair
    let (pk, sk) = {
        #[cfg(feature = "liboqs")]
        {
            let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).expect("ML-DSA-65 not available");
            sig.keypair().expect("oqs keypair failed")
        }
        #[cfg(not(feature = "liboqs"))]
        {
            let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
            (oqs::sig::PublicKey::from_bytes(pk.as_bytes()).unwrap(), oqs::sig::SecretKey::from_bytes(sk.as_bytes()).unwrap())
        }
    };

    // Restore RNG and clear state
    #[cfg(feature = "liboqs")]
    unsafe { OQS_randombytes_custom_algorithm(None); }
    {
        let mut guard = cell.lock().expect("rng mutex poisoned");
        if let Some(st) = guard.as_mut() { st.seed.zeroize(); }
        *guard = None;
    }

    // Output raw pk||sk
    let mut stdout = std::io::stdout();
    stdout.write_all(pk.as_ref()).expect("write pk failed");
    stdout.write_all(sk.as_ref()).expect("write sk failed");
    stdout.flush().ok();
}


