fn main() {
    // rust-embed 要求 web/dist 在编译期存在；前端未构建时创建空目录即可通过编译。
    let _ = std::fs::create_dir_all("web/dist");
}
