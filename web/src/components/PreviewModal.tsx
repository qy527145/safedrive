import { App, Modal, Spin, Tabs, Typography } from 'antd';
import { Suspense, lazy, useEffect, useRef, useState } from 'react';
import { streamUrl } from '../api/client';
import { formatBytes, previewKind } from '../utils/format';

const TEXT_PREVIEW_LIMIT = 2 * 1024 * 1024;
const OFFICE_PREVIEW_LIMIT = 20 * 1024 * 1024;
const SHEET_ROW_LIMIT = 300;
const SHEET_COL_LIMIT = 50;

/** markdown 渲染器体积不小，按需拆包；相对链接/图片改写到 /stream 以便直接显示。 */
const Markdown = lazy(async () => {
  const [md, gfm] = await Promise.all([import('react-markdown'), import('remark-gfm')]);
  const ReactMarkdown = md.default;
  const sanitize = md.defaultUrlTransform;
  return {
    default: ({ children, resolveRel }: { children: string; resolveRel: (rel: string) => string }) => (
      <ReactMarkdown
        remarkPlugins={[gfm.default]}
        urlTransform={(url) => {
          const safe = sanitize(url);
          if (!safe || /^[a-z][a-z0-9+.-]*:/i.test(safe) || safe.startsWith('/') || safe.startsWith('#')) {
            return safe;
          }
          return resolveRel(safe);
        }}
      >
        {children}
      </ReactMarkdown>
    ),
  };
});

interface SheetData {
  name: string;
  rows: string[][];
  truncated: boolean;
}

/**
 * 预览 / 播放器：media 元素直接指向 /stream URL —— 服务端流式解密并
 * 支持 Range/206，拖动进度条即发起新的区间请求。
 * markdown / docx / xlsx 在浏览器本地渲染，明文不出本机（零知识前提）。
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
  const [sheets, setSheets] = useState<SheetData[] | null>(null);
  const [docxReady, setDocxReady] = useState(false);
  const docxRef = useRef<HTMLDivElement>(null);

  const showError = (e: unknown) => message.error(e instanceof Error ? e.message : String(e));
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
  /** md 内的相对路径（../img/a.png）折算为同数据源内的明文路径再走 /stream。 */
  const resolveRel = (rel: string) => {
    let clean = rel;
    try { clean = decodeURIComponent(rel); } catch { /* 保留原样 */ }
    const segments = [...(dir ? dir.split('/') : []), ...clean.split('/')]
      .reduce<string[]>((acc, seg) => {
        if (seg === '' || seg === '.') return acc;
        if (seg === '..') acc.pop();
        else acc.push(seg);
        return acc;
      }, []);
    return streamUrl(dsId, segments.join('/'));
  };

  // 文本 / markdown：拉全文
  useEffect(() => {
    if (kind !== 'text' && kind !== 'markdown') return;
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
      .catch(showError);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, url]);

  // docx：docx-preview 本地渲染进容器
  useEffect(() => {
    if (kind !== 'docx') return;
    if (size > OFFICE_PREVIEW_LIMIT) {
      message.warning(`文件过大，仅支持预览 ${formatBytes(OFFICE_PREVIEW_LIMIT)} 以内的文档`);
      return;
    }
    let cancelled = false;
    (async () => {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`加载失败 (${r.status})`);
      const buf = await r.arrayBuffer();
      const { renderAsync } = await import('docx-preview');
      if (cancelled || !docxRef.current) return;
      await renderAsync(buf, docxRef.current, undefined, { ignoreLastRenderedPageBreak: true });
      if (!cancelled) setDocxReady(true);
    })().catch((e: unknown) => showError(e));
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, url]);

  // xlsx：exceljs 解析出表格数据，超限截断
  useEffect(() => {
    if (kind !== 'xlsx') return;
    if (size > OFFICE_PREVIEW_LIMIT) {
      setSheets([]);
      message.warning(`文件过大，仅支持预览 ${formatBytes(OFFICE_PREVIEW_LIMIT)} 以内的表格`);
      return;
    }
    let cancelled = false;
    (async () => {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`加载失败 (${r.status})`);
      const buf = await r.arrayBuffer();
      // exceljs 为 CJS 打包，兼容命名导出挂在 default 上的 interop 形态
      const mod = await import('exceljs');
      const Workbook = mod.Workbook
        ?? (mod as unknown as { default: { Workbook: typeof mod.Workbook } }).default.Workbook;
      const workbook = new Workbook();
      await workbook.xlsx.load(buf);
      if (cancelled) return;
      setSheets(workbook.worksheets.map((ws) => {
        const cols = Math.min(ws.columnCount, SHEET_COL_LIMIT);
        const rows: string[][] = [];
        ws.eachRow({ includeEmpty: true }, (row, rowNumber) => {
          if (rowNumber > SHEET_ROW_LIMIT) return;
          const cells: string[] = [];
          for (let c = 1; c <= cols; c += 1) cells.push(row.getCell(c).text ?? '');
          rows.push(cells);
        });
        return {
          name: ws.name,
          rows,
          truncated: ws.rowCount > SHEET_ROW_LIMIT || ws.columnCount > SHEET_COL_LIMIT,
        };
      }));
    })().catch((e: unknown) => { setSheets([]); showError(e); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, url]);

  const width =
    kind === 'video' ? 960
    : kind === 'pdf' || kind === 'docx' || kind === 'xlsx' ? 960
    : kind === 'markdown' ? 860
    : 720;
  const spinner = (
    <div style={{ textAlign: 'center', padding: 48 }}>
      <Spin />
    </div>
  );

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
      {kind === 'markdown' &&
        (text === null ? spinner : (
          <Suspense fallback={spinner}>
            <div className="md-preview">
              <Markdown resolveRel={resolveRel}>{text}</Markdown>
            </div>
          </Suspense>
        ))}
      {kind === 'docx' && (
        <div className="docx-preview-scroll">
          {!docxReady && spinner}
          <div ref={docxRef} />
        </div>
      )}
      {kind === 'xlsx' &&
        (sheets === null ? spinner : sheets.length === 0 ? (
          <Typography.Text type="secondary">无法预览该表格</Typography.Text>
        ) : (
          <Tabs
            items={sheets.map((sheet, i) => ({
              key: String(i),
              label: sheet.name,
              children: (
                <div className="sheet-preview">
                  <table>
                    <tbody>
                      {sheet.rows.map((row, ri) => (
                        // eslint-disable-next-line react/no-array-index-key
                        <tr key={ri}>
                          {row.map((cell, ci) => (
                            // eslint-disable-next-line react/no-array-index-key
                            <td key={ci}>{cell}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {sheet.truncated && (
                    <Typography.Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                      内容较多，仅预览前 {SHEET_ROW_LIMIT} 行 × {SHEET_COL_LIMIT} 列，完整内容请下载查看。
                    </Typography.Text>
                  )}
                </div>
              ),
            }))}
          />
        ))}
      {kind === 'text' &&
        (text === null ? spinner : <pre className="text-preview">{text}</pre>)}
      {kind === 'none' && <Typography.Text type="secondary">该类型不支持预览</Typography.Text>}
    </Modal>
  );
}
