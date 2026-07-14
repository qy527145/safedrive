import { App, Modal, Spin, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { streamUrl } from '../api/client';
import { formatBytes, previewKind } from '../utils/format';

const TEXT_PREVIEW_LIMIT = 2 * 1024 * 1024;

/**
 * 预览 / 播放器：media 元素直接指向 /stream URL —— 服务端流式解密并
 * 支持 Range/206，拖动进度条即发起新的区间请求。
 */
export default function PreviewModal({
  dsId,
  path,
  name,
  size,
  onClose,
}: {
  dsId: string;
  path: string;
  name: string;
  size: number;
  onClose: () => void;
}) {
  const { message } = App.useApp();
  const kind = previewKind(name);
  const url = streamUrl(dsId, path);
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    if (kind !== 'text') return;
    if (size > TEXT_PREVIEW_LIMIT) {
      setText(`（文件过大，仅支持预览 ${formatBytes(TEXT_PREVIEW_LIMIT)} 以内的文本）`);
      return;
    }
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error(`加载失败 (${r.status})`);
        return r.text();
      })
      .then(setText)
      .catch((e: unknown) => message.error(e instanceof Error ? e.message : String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, url]);

  const width = kind === 'video' ? 960 : kind === 'pdf' ? 900 : 720;

  return (
    <Modal title={name} open footer={null} width={width} onCancel={onClose} destroyOnHidden centered>
      {kind === 'image' && (
        <img
          src={url}
          alt={name}
          style={{ maxWidth: '100%', maxHeight: '70vh', display: 'block', margin: '0 auto' }}
        />
      )}
      {kind === 'video' && (
        // eslint-disable-next-line jsx-a11y/media-has-caption
        <video src={url} controls autoPlay style={{ width: '100%', maxHeight: '70vh', background: '#000' }} />
      )}
      {kind === 'audio' && (
        // eslint-disable-next-line jsx-a11y/media-has-caption
        <audio src={url} controls autoPlay style={{ width: '100%' }} />
      )}
      {kind === 'pdf' && (
        <iframe src={url} title={name} style={{ width: '100%', height: '70vh', border: 0 }} />
      )}
      {kind === 'text' &&
        (text === null ? (
          <div style={{ textAlign: 'center', padding: 48 }}>
            <Spin />
          </div>
        ) : (
          <pre
            style={{
              maxHeight: '65vh',
              overflow: 'auto',
              background: '#fafafa',
              padding: 12,
              borderRadius: 6,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {text}
          </pre>
        ))}
      {kind === 'none' && <Typography.Text type="secondary">该类型不支持预览</Typography.Text>}
    </Modal>
  );
}
