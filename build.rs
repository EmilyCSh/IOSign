use std::process::Command;

fn main() {
    let status = Command::new("make")
        .arg("-C")
        .arg("deps/zsign/build/linux")
        .arg("lib")
        .status()
        .expect("failed to run make for zsign");
    if !status.success() {
        panic!("Failed to build zsign library");
    }

    println!("cargo:rustc-link-search=native=deps/zsign/build/linux/.build");
    println!("cargo:rustc-link-lib=static=zsign");

    if let Ok(output) = Command::new("pkg-config").arg("--libs").arg("openssl").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            for token in s.split_whitespace() {
                if token.starts_with("-l") {
                    println!("cargo:rustc-link-lib={}", &token[2..]);
                } else if token.starts_with("-L") {
                    println!("cargo:rustc-link-search=native={}", &token[2..]);
                }
            }
        }
    }

    if let Ok(output) = Command::new("pkg-config").arg("--libs").arg("minizip").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            for token in s.split_whitespace() {
                if token.starts_with("-l") {
                    println!("cargo:rustc-link-lib={}", &token[2..]);
                } else if token.starts_with("-L") {
                    println!("cargo:rustc-link-search=native={}", &token[2..]);
                }
            }
        }
    }

    println!("cargo:rerun-if-changed=deps/zsign/src");
    println!("cargo:rustc-link-lib=stdc++");
}
