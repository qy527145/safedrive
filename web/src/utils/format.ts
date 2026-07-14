/** 展示格式化与预览类型判断。 */

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function formatTime(ms: number): string {
  if (!ms) return '-';
  const d = new Date(ms);
  const pad = (x: number) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function extOf(name: string): string {
  const i = name.lastIndexOf('.');
  return i < 0 ? '' : name.slice(i + 1).toLowerCase();
}

const IMAGE_EXTS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif']);
const VIDEO_EXTS = new Set(['mp4', 'webm', 'mkv', 'mov', 'm4v', 'avi', 'ts']);
const AUDIO_EXTS = new Set(['mp3', 'flac', 'wav', 'ogg', 'm4a', 'aac', 'opus']);
export const TEXT_EXTS = new Set([
  'txt', 'md', 'json', 'js', 'ts', 'tsx', 'jsx', 'css', 'html', 'xml', 'yml', 'yaml',
  'toml', 'ini', 'conf', 'log', 'sh', 'py', 'rs', 'go', 'java', 'c', 'cpp', 'h', 'csv',
]);

export type PreviewKind = 'image' | 'video' | 'audio' | 'pdf' | 'text' | 'none';

export function previewKind(name: string): PreviewKind {
  const ext = extOf(name);
  if (IMAGE_EXTS.has(ext)) return 'image';
  if (VIDEO_EXTS.has(ext)) return 'video';
  if (AUDIO_EXTS.has(ext)) return 'audio';
  if (ext === 'pdf') return 'pdf';
  if (TEXT_EXTS.has(ext)) return 'text';
  return 'none';
}

/** 解析人类可读大小："300M"、"1.5GB"、"512k"、纯数字（字节）。非法返回 null。 */
export function parseSize(input: string): number | null {
  const s = input.trim();
  if (!s) return null;
  const m = /^([\d.]+)\s*([a-zA-Z]*)$/.exec(s);
  if (!m) return null;
  const num = Number(m[1]);
  if (!Number.isFinite(num) || num < 0) return null;
  const mult: Record<string, number> = {
    '': 1, B: 1,
    K: 1024, KB: 1024, KIB: 1024,
    M: 1024 ** 2, MB: 1024 ** 2, MIB: 1024 ** 2,
    G: 1024 ** 3, GB: 1024 ** 3, GIB: 1024 ** 3,
  };
  const factor = mult[m[2].toUpperCase()];
  if (factor === undefined) return null;
  return Math.round(num * factor);
}

/** 字节数 → 便于回填输入框的字符串（整数优先："300M"、"1.5G"、"512K"）。 */
export function sizeToInput(bytes: number): string {
  const units: Array<[string, number]> = [['G', 1024 ** 3], ['M', 1024 ** 2], ['K', 1024]];
  for (const [u, f] of units) {
    if (bytes >= f && Number.isInteger(bytes / f * 100)) {
      const v = bytes / f;
      return Number.isInteger(v) ? `${v}${u}` : `${v.toFixed(2).replace(/0+$/, '').replace(/\.$/, '')}${u}`;
    }
  }
  return String(bytes);
}
