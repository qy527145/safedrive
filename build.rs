fn main() {
    // rust-embed 要求 web/dist 在编译期存在；前端未构建时创建空目录即可通过编译。
    // web/dist 已随仓库提交（cargo install --git），发布的 crate 包内也自带（见 Cargo.toml
    // include），两种安装方式都无需 bun/npm，此处均为 no-op。
    let _ = std::fs::create_dir_all("web/dist");
    // 前端产物变化时触发重新编译（release 下 rust-embed 在编译期嵌入资源）。
    println!("cargo:rerun-if-changed=web/dist");
}
