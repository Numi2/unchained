// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use risc0_build_kernel::{KernelBuild, KernelType};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let cxx_root = manifest_dir.join("cxx");
    println!("cargo:cxx_root={}", cxx_root.to_string_lossy());

    if env::var("CARGO_FEATURE_CUDA").is_ok() {
        println!(
            "cargo:cuda_root={}",
            manifest_dir.join("kernels/zkp/cuda").to_string_lossy()
        );
        build_cuda_kernels(&cxx_root);
    }

    if env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "macos" || os == "ios") {
        println!(
            "cargo:metal_root={}",
            manifest_dir.join("kernels/zkp/metal").to_string_lossy()
        );
        build_metal_kernels_or_stub();
    }
}

fn build_cuda_kernels(cxx_root: &Path) {
    KernelBuild::new(KernelType::Cuda)
        .files([
            "kernels/zkp/cuda/combos.cu",
            "kernels/zkp/cuda/eltwise.cu",
            "kernels/zkp/cuda/ffi.cu",
            "kernels/zkp/cuda/kernels.cu",
            "kernels/zkp/cuda/sha.cu",
            "kernels/zkp/cuda/supra/api.cu",
            "kernels/zkp/cuda/supra/ntt.cu",
        ])
        .deps(["kernels/zkp/cuda", "kernels/zkp/cuda/supra"])
        .flag("-DFEATURE_BABY_BEAR")
        .include(cxx_root)
        .include(env::var("DEP_BLST_C_SRC").unwrap())
        .include(env::var("DEP_SPPARK_ROOT").unwrap())
        .compile("risc0_zkp_cuda");
}

fn build_metal_kernels_or_stub() {
    let sdk_name = metal_sdk_name();
    if !metal_tools_available(sdk_name) {
        emit_placeholder_metal_kernel("metal_kernels_zkp");
        println!(
            "cargo:warning=Metal toolchain unavailable for SDK {sdk_name}; falling back to CPU-only RISC Zero proving"
        );
        return;
    }

    const METAL_KERNELS: &[(&str, &[&str])] = &[(
        "zkp",
        &[
            "eltwise.metal",
            "fri.metal",
            "mix.metal",
            "ntt.metal",
            "poseidon2.metal",
            "sha.metal",
            "zk.metal",
        ],
    )];

    let inc_path = Path::new("kernels/zkp/metal");
    for (name, srcs) in METAL_KERNELS {
        let dir = Path::new("kernels").join(name).join("metal");
        let src_paths = srcs.iter().map(|x| dir.join(x));
        let out = format!("metal_kernels_{name}");
        KernelBuild::new(KernelType::Metal)
            .files(src_paths)
            .include(inc_path)
            .dep(inc_path.join("sha256.h"))
            .compile(&out);
    }
}

fn metal_sdk_name() -> &'static str {
    let target = env::var("TARGET").unwrap();
    if target.ends_with("ios") {
        "iphoneos"
    } else if target.ends_with("ios-sim") {
        "iphonesimulator"
    } else if target.ends_with("darwin") {
        "macosx"
    } else {
        panic!("unsupported target: {target}")
    }
}

fn metal_tools_available(sdk_name: &str) -> bool {
    command_available(sdk_name, "metal") && command_available(sdk_name, "metallib")
}

fn command_available(sdk_name: &str, tool: &str) -> bool {
    Command::new("xcrun")
        .args(["--sdk", sdk_name, "--find", tool])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn emit_placeholder_metal_kernel(output: &str) {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).unwrap();
    let out_path = out_dir.join(format!("skip-{output}")).with_extension("metallib");
    fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&out_path)
        .unwrap();
    println!("cargo:{output}={}", out_path.display());
}
