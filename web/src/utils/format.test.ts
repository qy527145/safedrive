import { describe, expect, it } from 'vitest';
import { formatBytes, parseSize, previewKind, sizeToInput } from './format';

describe('formatBytes', () => {
  it('人类可读单位', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1024)).toBe('1.0 KiB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB');
    expect(formatBytes(3.5 * 1024 * 1024 * 1024)).toBe('3.5 GiB');
  });
});

describe('previewKind', () => {
  it('按扩展名判定', () => {
    expect(previewKind('电影.mp4')).toBe('video');
    expect(previewKind('照片.JPG')).toBe('image');
    expect(previewKind('音乐.flac')).toBe('audio');
    expect(previewKind('说明.pdf')).toBe('pdf');
    expect(previewKind('README.md')).toBe('text');
    expect(previewKind('archive.zip')).toBe('none');
    expect(previewKind('无扩展名')).toBe('none');
  });
});

describe('parseSize', () => {
  it('支持 K/KB/M/MB/G/GB 与纯数字', () => {
    expect(parseSize('300M')).toBe(300 * 1024 * 1024);
    expect(parseSize('300 MB')).toBe(300 * 1024 * 1024);
    expect(parseSize('1.5G')).toBe(1.5 * 1024 ** 3);
    expect(parseSize('512k')).toBe(512 * 1024);
    expect(parseSize('64KB')).toBe(64 * 1024);
    expect(parseSize('1048576')).toBe(1048576);
    expect(parseSize('')).toBeNull();
    expect(parseSize(undefined)).toBeNull();
    expect(parseSize(null)).toBeNull();
    expect(parseSize('abc')).toBeNull();
    expect(parseSize('5T')).toBeNull();
  });
});

describe('sizeToInput', () => {
  it('往返一致', () => {
    expect(sizeToInput(300 * 1024 * 1024)).toBe('300M');
    expect(sizeToInput(5 * 1024 * 1024)).toBe('5M');
    expect(sizeToInput(512 * 1024)).toBe('512K');
    expect(parseSize(sizeToInput(1.5 * 1024 ** 3))).toBe(1.5 * 1024 ** 3);
  });
});
