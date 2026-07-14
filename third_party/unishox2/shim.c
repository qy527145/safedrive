/* SafeDrive 薄封装：以默认 preset + 显式输出缓冲长度暴露 Unishox2。
 * 需与 unishox2.c 一起以 -DUNISHOX_API_WITH_OUTPUT_LEN=1 编译。 */
#include "unishox2.h"

int sd_unishox2_compress(const char *in, int len, char *out, int olen) {
  return unishox2_compress(in, len, out, olen, USX_PSET_DFLT);
}

int sd_unishox2_decompress(const char *in, int len, char *out, int olen) {
  return unishox2_decompress(in, len, out, olen, USX_PSET_DFLT);
}
