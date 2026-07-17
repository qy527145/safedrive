import {
  AppstoreOutlined,
  ArrowLeftOutlined,
  BarsOutlined,
  ClearOutlined,
  CloudDownloadOutlined,
  DeleteOutlined,
  DownOutlined,
  DownloadOutlined,
  EditOutlined,
  EyeOutlined,
  FileOutlined,
  FolderAddOutlined,
  FolderOutlined,
  LinkOutlined,
  ImportOutlined,
  MoreOutlined,
  PauseCircleOutlined,
  ReloadOutlined,
  UnlockOutlined,
  UploadOutlined,
} from '@ant-design/icons';
import {
  App,
  Breadcrumb,
  Button,
  Card,
  Checkbox,
  Dropdown,
  Empty,
  Input,
  Segmented,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { InputRef, MenuProps } from 'antd';
import type { ChangeEvent, DragEvent } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, streamUrl, uploadFile, type FileCacheStatus, type FsEntry } from '../api/client';
import PreviewModal from '../components/PreviewModal';
import { useSources } from '../stores/sources';
import { taskProgress, taskUploaded, useTasks } from '../stores/tasks';
import { formatBytes, formatTime, previewKind } from '../utils/format';
import { useTransfers } from '../stores/transfers';

type UploadCandidate = { file: File; relativePath: string };

type DroppedFileEntry = {
  isFile: true;
  isDirectory: false;
  fullPath: string;
  file: (success: (file: File) => void, error?: (error: DOMException) => void) => void;
};

type DroppedDirectoryEntry = {
  isFile: false;
  isDirectory: true;
  createReader: () => {
    readEntries: (
      success: (entries: DroppedEntry[]) => void,
      error?: (error: DOMException) => void,
    ) => void;
  };
};

type DroppedEntry = DroppedFileEntry | DroppedDirectoryEntry;

const readDroppedFile = (entry: DroppedFileEntry) =>
  new Promise<File>((resolve, reject) => entry.file(resolve, reject));

/** readEntries 每次只保证返回一批，目录较大时必须一直读取到空批次。 */
async function readDroppedDirectory(entry: DroppedDirectoryEntry): Promise<DroppedEntry[]> {
  const reader = entry.createReader();
  const result: DroppedEntry[] = [];
  while (true) {
    const batch = await new Promise<DroppedEntry[]>((resolve, reject) =>
      reader.readEntries(resolve, reject),
    );
    if (batch.length === 0) return result;
    result.push(...batch);
  }
}

async function filesFromDroppedEntry(entry: DroppedEntry): Promise<UploadCandidate[]> {
  if (entry.isFile) {
    const file = await readDroppedFile(entry);
    return [{ file, relativePath: entry.fullPath.replace(/^\/+/, '') || file.name }];
  }
  const children = await readDroppedDirectory(entry);
  return (await Promise.all(children.map(filesFromDroppedEntry))).flat();
}

async function filesFromDrop(dataTransfer: DataTransfer): Promise<UploadCandidate[]> {
  const entries = Array.from(dataTransfer.items)
    .filter((item) => item.kind === 'file')
    .map((item) =>
      (item as unknown as { webkitGetAsEntry?: () => DroppedEntry | null })
        .webkitGetAsEntry?.() ?? null,
    )
    .filter((entry): entry is DroppedEntry => entry !== null);

  if (entries.length > 0) return (await Promise.all(entries.map(filesFromDroppedEntry))).flat();
  return Array.from(dataTransfer.files).map((file) => ({ file, relativePath: file.name }));
}

/** 加密文件浏览器：与服务端只交换明文路径，加解密全部发生在服务端。 */
export default function BrowserPage() {
  const { dsId = '' } = useParams();
  const navigate = useNavigate();
  const { message, modal } = App.useApp();
  const sources = useSources();
  const enqueue = useTasks((s) => s.enqueue);

  const ds = sources.list.find((d) => d.id === dsId);
  // 当前目录放在 URL 查询参数里（?path=a/b），进入子目录会 push 历史记录，
  // 浏览器前进/后退沿目录层级走，刷新也能停留在原目录。
  const [searchParams, setSearchParams] = useSearchParams();
  const curPath = searchParams.get('path') ?? '';
  const stack = useMemo(() => (curPath ? curPath.split('/') : []), [curPath]);
  const gotoPath = useCallback(
    (path: string) => setSearchParams(path ? { path } : {}),
    [setSearchParams],
  );
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [selectedNames, setSelectedNames] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [draggingFiles, setDraggingFiles] = useState(false);
  const dragDepth = useRef(0);
  const [preview, setPreview] = useState<{ path: string; name: string; size: number } | null>(null);
  // 呈现方式：列表（表格）/ 卡片（网格），记忆在本地
  const [view, setView] = useState<'list' | 'card'>(() =>
    localStorage.getItem('sd.view.files') === 'card' ? 'card' : 'list',
  );
  const changeView = (v: 'list' | 'card') => {
    setView(v);
    localStorage.setItem('sd.view.files', v);
  };

  const joinPath = useCallback(
    (name: string) => (curPath ? `${curPath}/${name}` : name),
    [curPath],
  );

  const refresh = useCallback(async () => {
    if (!dsId) return;
    setLoading(true);
    try {
      setEntries(await api.listFiles(dsId, curPath));
      setSelectedNames([]);
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [dsId, curPath, message]);

  useEffect(() => {
    void sources.refresh().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // ---------- 上传 ----------
  const filePicker = useRef<HTMLInputElement>(null);
  const folderPicker = useRef<HTMLInputElement>(null);
  const enqueueUploads = (files: UploadCandidate[]) => {
    const existing = new Set(entries.map((e) => e.name));
    for (const { file, relativePath } of files) {
      const rel = relativePath.replace(/\\/g, '/');
      const top = rel.split('/')[0];
      if (rel === file.name && existing.has(top)) {
        message.warning(`已存在同名条目，跳过: ${top}`);
        continue;
      }
      const target = joinPath(rel);
      const id = crypto.randomUUID();
      enqueue(
        {
          id,
          kind: 'upload',
          name: rel,
          dsName: ds?.name ?? '',
          totalBytes: file.size,
        },
        async (_task, signal) => {
          const { promise, cancel } = uploadFile(
            dsId,
            target,
            file,
            () => undefined,
            id,
          );
          signal.addEventListener('abort', cancel);
          // 两个维度都以服务端为准：encrypted = 已加密并切入分卷，uploaded = 网盘已确认。
          const poll = window.setInterval(() => {
            api
              .uploadProgress(id)
              .then((p) => {
                taskProgress(id, p.encrypted);
                taskUploaded(id, p.uploaded);
              })
              .catch(() => undefined);
          }, 500);
          try {
            await promise;
          } finally {
            window.clearInterval(poll);
            signal.removeEventListener('abort', cancel);
          }
          void refresh();
        },
      );
    }
  };

  const pickerCandidates = (files: File[]) => files.map((file) => ({
    file,
    // 文件夹选择带 webkitRelativePath（"目录/子目录/文件"），普通选择为空。
    relativePath: (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name,
  }));

  const onPickerChange = (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files ?? []);
    event.target.value = '';
    if (files.length) enqueueUploads(pickerCandidates(files));
  };

  const isFileDrag = (event: DragEvent) =>
    Array.from(event.dataTransfer.types).includes('Files');

  const onDragEnter = (event: DragEvent<HTMLDivElement>) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth.current += 1;
    setDraggingFiles(true);
  };

  const onDragOver = (event: DragEvent<HTMLDivElement>) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  };

  const onDragLeave = (event: DragEvent<HTMLDivElement>) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDraggingFiles(false);
  };

  const onDrop = async (event: DragEvent<HTMLDivElement>) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth.current = 0;
    setDraggingFiles(false);
    try {
      const files = await filesFromDrop(event.dataTransfer);
      if (files.length === 0) {
        message.warning('没有找到可上传的文件（空文件夹暂不支持上传）');
        return;
      }
      enqueueUploads(files);
    } catch (error) {
      message.error(`读取拖入内容失败: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  // ---------- 下载 / 预览 ----------
  const downloadAction = (item: FsEntry) => {
    // 服务端流式解密，浏览器原生下载（<a> 导航到 /stream?dl=1）
    const a = document.createElement('a');
    a.href = streamUrl(dsId, joinPath(item.name), { dl: true });
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const copyStreamLink = async (item: FsEntry) => {
    const url = new URL(streamUrl(dsId, joinPath(item.name)), window.location.origin);
    await navigator.clipboard.writeText(url.toString());
    message.success('播放链接已复制（可直接粘贴到 VLC / IINA / 其他设备）');
  };

  const refreshCacheStatus = useCallback(async (name: string) => {
    const path = joinPath(name);
    try {
      const cache = await api.fileCacheStatus(dsId, path);
      setEntries((current) => current.map((entry) => entry.name === name ? {...entry, cache} : entry));
    } catch { /* 文件已删除或页面切换，忽略 */ }
  }, [dsId, joinPath]);

  // 缓存操作（列表视图的按钮与卡片视图的菜单共用）
  const warmAction = async (item: FsEntry) => {
    await api.warmFileCache(dsId, joinPath(item.name));
    message.success('已开始在服务端缓存，可观察实时下行速度');
    void refreshCacheStatus(item.name);
  };
  const stopWarmAction = async (item: FsEntry) => {
    await api.stopWarmFileCache(dsId, joinPath(item.name));
    message.success('已停止主动缓存任务；播放/下载经过服务器时仍会自动缓存');
    void refreshCacheStatus(item.name);
  };
  const clearCacheAction = async (item: FsEntry) => {
    const r = await api.clearFileCache(dsId, joinPath(item.name));
    message.success(`已清理 ${formatBytes(r.freed)}`);
    await refresh();
  };

  const entriesRef = useRef<FsEntry[]>([]);
  entriesRef.current = entries;

  // 缓存进度实时化：无论是手动预热还是播放/下载的写透缓存，只要该文件
  // 正在预热（warming）或有实时下行流量（= 正在回源写缓存），就每秒刷新
  // 其真实缓存状态；命中缓存的播放没有下行流量，也不会产生新缓存，不刷。
  useEffect(() => {
    if (!ds?.cacheEnabled) return;
    const inflight = new Set<string>();
    const timer = window.setInterval(() => {
      const speeds = useTransfers.getState().snapshot.fileDownloadSpeeds;
      for (const entry of entriesRef.current) {
        if (entry.isDir || entry.foreign || !entry.cache || entry.cache.complete) continue;
        const active = entry.cache.warming
          || (speeds[`${dsId}:${joinPath(entry.name)}`] ?? 0) > 0;
        if (!active || inflight.has(entry.name)) continue;
        inflight.add(entry.name);
        void refreshCacheStatus(entry.name).finally(() => inflight.delete(entry.name));
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [ds?.cacheEnabled, dsId, joinPath, refreshCacheStatus]);

  // ---------- 删除 / 重命名 / 新建目录 ----------
  const deleteAction = (item: FsEntry) => {
    modal.confirm({
      title: `删除「${item.name}」？`,
      content: item.isDir ? '将递归删除云端密文与密码本中的对应密钥。' : '云端密文与密钥都会被删除。',
      okButtonProps: { danger: true },
      onOk: async () => {
        await api.deletePath(dsId, joinPath(item.name));
        message.success('已删除');
        await refresh();
      },
    });
  };

  const deleteForeignAction = (item: FsEntry) => {
    modal.confirm({
      title: `删除外来条目「${item.name}」？`,
      content: '该条目不由密码本管理（可能是其他工具写入的文件），将直接从云端删除。',
      okButtonProps: { danger: true },
      onOk: async () => {
        await api.deleteForeign(dsId, curPath, item.name);
        message.success('已删除');
        await refresh();
      },
    });
  };

  const nameInput = useRef<InputRef>(null);

  /** 解密外来条目：输入其原加密密码（f_key），服务端解开信封后换当前
   * 链路密码重新封装名字（一次 rename）。密码不对时弹窗提示，不 rename。 */
  const adoptForeignAction = (item: FsEntry) => {
    let value = '';
    modal.confirm({
      title: `解密外来条目「${item.name}」`,
      icon: <UnlockOutlined />,
      content: (
        <Space direction="vertical" style={{ width: '100%' }}>
          <Typography.Text type="secondary">
            输入该条目原来的加密密码（分享方的数据源密码，或 base64 目录密钥）。
            解密成功后将改用当前目录的链路密码重新封装，之后即可正常浏览。
          </Typography.Text>
          <Input.Password
            ref={nameInput}
            placeholder="原加密密码（f_key）"
            onChange={(e) => (value = e.target.value)}
          />
        </Space>
      ),
      okText: '解密',
      onOk: async () => {
        const password = value.trim();
        if (!password) throw new Error('请输入密码');
        try {
          const r = await api.adoptForeign(dsId, curPath, item.name, password);
          message.success(`已解密并纳入当前目录：${r.name}`);
          await refresh();
        } catch (e) {
          modal.error({
            title: '解密失败',
            content: e instanceof Error ? e.message : String(e),
          });
          throw e; // 保留输入弹窗，便于更正后重试
        }
      },
    });
    setTimeout(() => nameInput.current?.focus(), 100);
  };

  const renameAction = (item: FsEntry) => {
    let value = item.name;
    modal.confirm({
      title: `重命名「${item.name}」`,
      icon: <EditOutlined />,
      content: (
        <Input
          ref={nameInput}
          defaultValue={item.name}
          onChange={(e) => (value = e.target.value)}
          onFocus={(e) => e.target.select()}
        />
      ),
      onOk: async () => {
        const next = value.trim();
        if (!next || next === item.name) return;
        if (next.includes('/')) throw new Error('名称不能包含 /');
        await api.rename(dsId, joinPath(item.name), joinPath(next));
        message.success('已重命名');
        await refresh();
      },
    });
    setTimeout(() => nameInput.current?.focus(), 100);
  };

  const newFolderAction = () => {
    let value = '';
    modal.confirm({
      title: '新建目录',
      icon: <FolderAddOutlined />,
      content: <Input ref={nameInput} placeholder="目录名" onChange={(e) => (value = e.target.value)} />,
      onOk: async () => {
        const name = value.trim();
        if (!name) throw new Error('目录名不能为空');
        if (name.includes('/')) throw new Error('名称不能包含 /');
        await api.mkdir(dsId, joinPath(name));
        message.success('已创建');
        await refresh();
      },
    });
    setTimeout(() => nameInput.current?.focus(), 100);
  };

  // ---------- 云盘分享 ----------
  const createShareAction = async () => {
    if (selectedNames.length === 0) {
      message.warning('请先选择要分享的文件或文件夹');
      return;
    }
    let result: { link: string };
    try {
      result = await api.createShare(dsId, selectedNames.map(joinPath));
    } catch (error) {
      message.error(error instanceof Error ? error.message : String(error));
      return;
    }
    modal.confirm({
      title: `已创建分享（${selectedNames.length} 项）`,
      icon: <LinkOutlined />,
      content: <Space direction="vertical" style={{ width: '100%' }}>
        <Typography.Text type="warning">链接包含提取码和解密信息，请只发给可信接收者。</Typography.Text>
        <Input.TextArea readOnly value={result.link} autoSize={{ minRows: 4, maxRows: 8 }} onFocus={(e) => e.target.select()} />
      </Space>,
      okText: '复制链接',
      cancelText: '关闭',
      onOk: async () => {
        await navigator.clipboard.writeText(result.link);
        message.success('标准分享链接已复制');
      },
    });
  };

  const importShareAction = () => {
    let link = '';
    const run = async (force: boolean) => {
      const result = await api.importShare(dsId, link.trim(), curPath, force);
      message.success(`已导入 ${result.imported} 项`);
      await refresh();
    };
    modal.confirm({
      title: '导入分享',
      icon: <ImportOutlined />,
      content: <Input.TextArea autoSize={{ minRows: 4, maxRows: 8 }} placeholder="粘贴 sd:// 分享链接" onChange={(e) => { link = e.target.value; }} />,
      okText: '导入到当前目录',
      onOk: async () => {
        if (!link.trim()) throw new Error('请粘贴分享链接');
        try {
          await run(false);
        } catch (error) {
          const text = error instanceof Error ? error.message : String(error);
          if (!text.includes('加密模式不兼容')) throw error;
          modal.confirm({
            title: '加密模式不兼容',
            content: `${text}。仍要继续吗？`,
            okText: '仍然导入',
            okButtonProps: { danger: true },
            onOk: () => run(true),
          });
        }
      },
    });
  };

  // ---------- 行为 ----------
  const onNameClick = (item: FsEntry) => {
    if (item.foreign) return;
    if (item.isDir) {
      gotoPath(joinPath(item.name));
      return;
    }
    if (previewKind(item.name) === 'none') {
      message.info('该类型不支持预览，请直接下载');
      return;
    }
    setPreview({ path: joinPath(item.name), name: item.name, size: item.size });
  };

  /** 卡片视图的条目操作菜单（能力与列表视图的操作列对齐）。 */
  const entryMenuItems = (item: FsEntry): MenuProps['items'] => {
    if (item.foreign) {
      const foreignItems: MenuProps['items'] = [];
      if (item.isDir) {
        // 受管加密条目在存储端总是文件夹；只有这类外来条目才可能解密纳管
        foreignItems.push({
          key: 'adopt-foreign',
          icon: <UnlockOutlined />,
          label: '输入密码解密',
          onClick: () => adoptForeignAction(item),
        });
      }
      foreignItems.push({
        key: 'delete-foreign',
        danger: true,
        icon: <DeleteOutlined />,
        label: '删除外来条目',
        onClick: () => deleteForeignAction(item),
      });
      return foreignItems;
    }
    const items: MenuProps['items'] = [];
    if (!item.isDir) {
      if (previewKind(item.name) !== 'none') {
        items.push({ key: 'preview', icon: <EyeOutlined />, label: '预览', onClick: () => onNameClick(item) });
      }
      items.push({ key: 'download', icon: <DownloadOutlined />, label: '下载', onClick: () => downloadAction(item) });
      items.push({ key: 'link', icon: <LinkOutlined />, label: '复制播放链接', onClick: () => void copyStreamLink(item) });
      if (ds?.cacheEnabled) {
        if (item.cache?.warming) {
          items.push({ key: 'cache-stop', icon: <PauseCircleOutlined />, label: '停止缓存', onClick: () => void stopWarmAction(item) });
        } else if (!item.cache?.complete) {
          items.push({ key: 'cache-warm', icon: <CloudDownloadOutlined />, label: '服务端缓存', onClick: () => void warmAction(item) });
        }
        if (item.cache?.cached && !item.cache.warming) {
          items.push({ key: 'cache-clear', icon: <ClearOutlined />, label: '清理缓存', onClick: () => void clearCacheAction(item) });
        }
      }
      items.push({ type: 'divider' });
    }
    items.push({ key: 'rename', icon: <EditOutlined />, label: '重命名', onClick: () => renameAction(item) });
    items.push({ key: 'delete', danger: true, icon: <DeleteOutlined />, label: '删除', onClick: () => deleteAction(item) });
    return items;
  };

  if (sources.loaded && !ds) {
    return (
      <Card>
        <Typography.Text type="danger">数据源不存在</Typography.Text>
      </Card>
    );
  }

  return (
    <div
      className={`file-drop-zone${draggingFiles ? ' is-dragging' : ''}`}
      onDragEnter={onDragEnter}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={(event) => void onDrop(event)}
    >
      {draggingFiles && (
        <div className="file-drop-overlay" aria-hidden="true">
          <UploadOutlined />
          <strong>拖放到这里上传</strong>
          <span>支持文件和文件夹，将上传到当前目录</span>
        </div>
      )}
      <input ref={filePicker} type="file" multiple hidden onChange={onPickerChange} />
      <input
        ref={folderPicker}
        type="file"
        multiple
        hidden
        {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
        onChange={onPickerChange}
      />
      <Card
      title={
        <Space size={4}>
          <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/')} />
          {/* 面包屑以数据源为根，逐层可点击回跳 */}
          <Breadcrumb
            items={[
              {
                title:
                  stack.length === 0 ? (
                    <span>{ds?.name ?? '…'}</span>
                  ) : (
                    <a onClick={() => gotoPath('')}>{ds?.name ?? '…'}</a>
                  ),
              },
              ...stack.map((name, i) => ({
                title:
                  i === stack.length - 1 ? (
                    <span>{name}</span>
                  ) : (
                    <a onClick={() => gotoPath(stack.slice(0, i + 1).join('/'))}>{name}</a>
                  ),
              })),
            ]}
          />
        </Space>
      }
      extra={
        <Space>
          <Segmented
            value={view}
            onChange={(v) => changeView(v as 'list' | 'card')}
            options={[
              { value: 'list', icon: <BarsOutlined />, title: '列表视图' },
              { value: 'card', icon: <AppstoreOutlined />, title: '卡片视图' },
            ]}
          />
          <Dropdown
            menu={{ items: [
              { key: 'files', label: '选择文件（可多选）', onClick: () => filePicker.current?.click() },
              { key: 'folder', label: '选择文件夹', onClick: () => folderPicker.current?.click() },
            ] }}
          >
            <Button type="primary" icon={<UploadOutlined />}>
              上传 <DownOutlined />
            </Button>
          </Dropdown>
          {ds?.type === 'baidupan' && <Button icon={<LinkOutlined />} disabled={!selectedNames.length} onClick={() => void createShareAction()}>
            分享{selectedNames.length ? ` (${selectedNames.length})` : ''}
          </Button>}
          {ds?.type === 'baidupan' && <Button icon={<ImportOutlined />} onClick={importShareAction}>导入分享</Button>}
          <Button icon={<FolderAddOutlined />} onClick={newFolderAction}>
            新建目录
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => void refresh()} />
        </Space>
      }
    >
      {view === 'card' ? (
        <Spin spinning={loading}>
          {entries.length === 0 ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="空目录"
              style={{ padding: '48px 0' }}
            />
          ) : (
            <div className="file-grid">
              {entries.map((item) => (
                <div
                  key={`${item.foreign ? 'f' : 'm'}:${item.name}`}
                  className={`file-tile${item.foreign ? ' foreign' : ''}`}
                  onClick={() => onNameClick(item)}
                >
                  {!item.foreign && ds?.type === 'baidupan' && <Checkbox
                    checked={selectedNames.includes(item.name)}
                    onClick={(event) => event.stopPropagation()}
                    onChange={(event) => setSelectedNames((current) => event.target.checked
                      ? [...current, item.name]
                      : current.filter((name) => name !== item.name))}
                    style={{ position: 'absolute', left: 10, top: 10 }}
                  />}
                  <div className="file-tile-icon">
                    {item.isDir ? (
                      <FolderOutlined style={{ color: '#faad14' }} />
                    ) : (
                      <FileOutlined style={{ color: '#8c8c8c' }} />
                    )}
                  </div>
                  <div className="file-tile-name" title={item.name}>
                    {item.name}
                  </div>
                  <div className="file-tile-meta">
                    {item.foreign ? <Tag>外来</Tag> : item.isDir ? '目录' : formatBytes(item.size)}
                  </div>
                  <Dropdown menu={{ items: entryMenuItems(item) }} trigger={['click']}>
                    <Button
                      className="file-tile-more"
                      type="text"
                      size="small"
                      icon={<MoreOutlined />}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </Dropdown>
                </div>
              ))}
            </div>
          )}
        </Spin>
      ) : (
      <Table<FsEntry>
        rowKey="name"
        dataSource={entries}
        loading={loading}
        pagination={false}
        size="middle"
        rowSelection={ds?.type === 'baidupan' ? {
          selectedRowKeys: selectedNames,
          getCheckboxProps: (item) => ({ disabled: item.foreign }),
          onChange: (keys) => setSelectedNames(keys.map(String)),
        } : undefined}
        columns={[
          {
            title: '名称',
            key: 'name',
            render: (_, item) => (
              <Space>
                {item.isDir ? (
                  <FolderOutlined style={{ color: '#faad14' }} />
                ) : (
                  <FileOutlined style={{ color: '#8c8c8c' }} />
                )}
                {item.foreign ? (
                  <Typography.Text type="secondary">
                    {item.name} <Tag>外来</Tag>
                  </Typography.Text>
                ) : (
                  <Typography.Link onClick={() => onNameClick(item)}>{item.name}</Typography.Link>
                )}
              </Space>
            ),
          },
          {
            title: '大小',
            dataIndex: 'size',
            width: 120,
            render: (v: number, item) => (item.isDir ? '-' : formatBytes(v)),
          },
          {
            title: '修改时间',
            dataIndex: 'mtime',
            width: 170,
            render: (v: number) => formatTime(v),
          },
          {
            title: '实时下行',
            width: 120,
            render: (_, item) => item.isDir ? '-' : <LiveFileSpeed
              identity={`${dsId}:${joinPath(item.name)}`} fallback={item.downloadSpeed ?? 0} />,
          },
          {
            title: '缓存',
            width: 200,
            render: (_, item) => item.isDir || item.foreign ? '-' : (
              <Space size="small">
                <Tooltip
                  // 热力条内容宽 320px，需放宽气泡（antd 默认 max-width 250px 会溢出）
                  overlayStyle={{ maxWidth: 380 }}
                  title={item.cache && item.cache.bitmapSummary.length > 0 && (item.cache.cached || item.cache.warming)
                    ? <CacheStrip cache={item.cache} /> : undefined}
                >
                  <Tag color={item.cache?.complete ? 'success' : item.cache?.warming ? 'processing' : item.cache?.cached ? 'warning' : 'default'}>
                    {item.cache?.complete ? '完整' : item.cache?.cached
                      ? `${formatBytes(item.cache.bytesCached)}` : item.cache?.warming ? '缓存中' : '未缓存'}
                  </Tag>
                </Tooltip>
                {!item.cache?.complete && !item.cache?.warming && ds?.cacheEnabled && <Button size="small" onClick={() => void warmAction(item)}>缓存</Button>}
                {item.cache?.warming && <Button size="small" onClick={() => void stopWarmAction(item)}>停止</Button>}
                {!item.cache?.warming && item.cache?.cached && <Button size="small" danger onClick={() => void clearCacheAction(item)}>清理</Button>}
              </Space>
            ),
          },
          {
            title: '操作',
            key: 'ops',
            width: 220,
            render: (_, item) =>
              item.foreign ? (
                <Space>
                  {item.isDir && (
                    <Tooltip title="输入密码解密">
                      <Button
                        size="small"
                        icon={<UnlockOutlined />}
                        onClick={() => adoptForeignAction(item)}
                      />
                    </Tooltip>
                  )}
                  <Tooltip title="删除外来条目">
                    <Button
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                      onClick={() => deleteForeignAction(item)}
                    />
                  </Tooltip>
                </Space>
              ) : (
                <Space>
                  {!item.isDir && previewKind(item.name) !== 'none' && (
                    <Tooltip title="预览">
                      <Button size="small" icon={<EyeOutlined />} onClick={() => onNameClick(item)} />
                    </Tooltip>
                  )}
                  {!item.isDir && (
                    <Tooltip title="下载">
                      <Button
                        size="small"
                        icon={<DownloadOutlined />}
                        onClick={() => downloadAction(item)}
                      />
                    </Tooltip>
                  )}
                  {!item.isDir && (
                    <Tooltip title="复制播放链接">
                      <Button
                        size="small"
                        icon={<LinkOutlined />}
                        onClick={() => void copyStreamLink(item)}
                      />
                    </Tooltip>
                  )}
                  <Tooltip title="重命名">
                    <Button size="small" icon={<EditOutlined />} onClick={() => renameAction(item)} />
                  </Tooltip>
                  <Tooltip title="删除">
                    <Button
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                      onClick={() => deleteAction(item)}
                    />
                  </Tooltip>
                </Space>
              ),
          },
        ]}
      />
      )}

      {preview && (
        <PreviewModal
          dsId={dsId}
          path={preview.path}
          name={preview.name}
          size={preview.size}
          onClose={() => setPreview(null)}
        />
      )}
      </Card>
    </div>
  );
}

function LiveFileSpeed({ identity, fallback }: { identity: string; fallback: number }) {
  const speed = useTransfers((state) => state.snapshot.fileDownloadSpeeds[identity] ?? fallback);
  return <span className="mono-metric">{formatBytes(speed)}/s</span>;
}

/**
 * 缓存分布热力条（取自 hydraria 的 block-bitmap heat strip）：
 * 每段代表文件的一个连续区段，亮度随该区段缓存比例从暗到亮；
 * 悬停单段可见对应字节区间，直观看到「缓存了哪部分」。
 */
function CacheStrip({ cache }: { cache: FileCacheStatus }) {
  const buckets = cache.bitmapSummary;
  const total = cache.totalSize;
  if (!buckets.length || !total) return null;
  const pctTotal = Math.min(100, Math.round((cache.bytesCached / total) * 100));
  return (
    <div style={{ width: 320, padding: '2px 0' }}>
      <div style={{ display: 'flex', height: 10, gap: 1, borderRadius: 3, overflow: 'hidden' }}>
        {buckets.map((pct, i) => {
          const lo = Math.floor((i * total) / buckets.length);
          const hi = Math.floor(((i + 1) * total) / buckets.length) - 1;
          // pct 0..100 → 亮度 0.08..1.0
          const alpha = (0.08 + (pct / 100) * 0.92).toFixed(2);
          return (
            <div
              key={i}
              title={`已缓存 ${pct}% · 字节 ${lo}-${hi}`}
              style={{ flex: 1, background: `rgba(110, 168, 255, ${alpha})` }}
            />
          );
        })}
      </div>
      <div style={{ marginTop: 6, fontSize: 12, opacity: 0.75 }}>
        已缓存 {formatBytes(cache.bytesCached)} / {formatBytes(total)}（{pctTotal}%）· 亮色为已缓存区段
      </div>
    </div>
  );
}
