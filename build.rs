fn main() {
    // rust-embed 要求 web/dist 在编译期存在；前端未构建时创建空目录即可通过编译。
    let _ = std::fs::create_dir_all("web/dist");

    // Unishox2 短字符串压缩（文件名加密前压缩，Apache-2.0，见 third_party/unishox2/）。
    // UNISHOX_API_WITH_OUTPUT_LEN=1：API 携带输出缓冲区长度，越界返回错误而非写穿。
    println!("cargo:rerun-if-changed=third_party/unishox2/unishox2.c");
    println!("cargo:rerun-if-changed=third_party/unishox2/unishox2.h");
    println!("cargo:rerun-if-changed=third_party/unishox2/shim.c");
    cc::Build::new()
        .file("third_party/unishox2/unishox2.c")
        .file("third_party/unishox2/shim.c")
        .include("third_party/unishox2")
        .define("UNISHOX_API_WITH_OUTPUT_LEN", "1")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .opt_level(2)
        .compile("unishox2");
}
