# Unishox2 (vendored)

- 来源：https://github.com/siara-cc/Unishox2（Apache-2.0，见 LICENSE）
- 用途：文件名加密前的短字符串压缩（`src/crypto/unishox2.rs` 薄 FFI）
- 编译：build.rs 以 `UNISHOX_API_WITH_OUTPUT_LEN=1` 开启输出缓冲区边界检查
