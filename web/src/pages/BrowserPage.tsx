import {
  ArrowLeftOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  EyeOutlined,
  FileOutlined,
  FolderAddOutlined,
  FolderOutlined,
  LinkOutlined,
  ReloadOutlined,
  UploadOutlined,
} from '@ant-design/icons';
import {
  App,
  Breadcrumb,
  Button,
  Card,
  Input,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
} from 'antd';
import type { InputRef } from 'antd';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api, streamUrl, uploadFile, type FsEntry } from '../api/client';
import PreviewModal from '../components/PreviewModal';
import { useSources } from '../stores/sources';
import { taskProgress, useTasks } from '../stores/tasks';
import { formatBytes, formatTime, previewKind } from '../utils/format';

/** 加密文件浏览器：与服务端只交换明文路径，加解密全部发生在服务端。 */
export default function BrowserPage() {
  const { dsId = '' } = useParams();
  const navigate = useNavigate();
  const { message, modal } = App.useApp();
  const sources = useSources();
  const enqueue = useTasks((s) => s.enqueue);

  const ds = sources.list.find((d) => d.id === dsId);
  const [stack, setStack] = useState<string[]>([]);
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<{ path: string; name: string; size: number } | null>(null);

  const curPath = useMemo(() => stack.join('/'), [stack]);
  const joinPath = useCallback(
    (name: string) => (curPath ? `${curPath}/${name}` : name),
    [curPath],
  );

  const refresh = useCallback(async () => {
    if (!dsId) return;
    setLoading(true);
    try {
      setEntries(await api.listFiles(dsId, curPath));
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
  const enqueueUploads = (files: File[]) => {
    const existing = new Set(entries.map((e) => e.name));
    for (const file of files) {
      // 文件夹上传带 webkitRelativePath（"目录/子目录/文件"），普通上传为空
      const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
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
          const { promise, cancel } = uploadFile(dsId, target, file, (sent) =>
            taskProgress(id, sent),
          );
          signal.addEventListener('abort', cancel);
          try {
            await promise;
          } finally {
            signal.removeEventListener('abort', cancel);
          }
          void refresh();
        },
      );
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

  // ---------- 行为 ----------
  const onNameClick = (item: FsEntry) => {
    if (item.foreign) return;
    if (item.isDir) {
      setStack((s) => [...s, item.name]);
      return;
    }
    if (previewKind(item.name) === 'none') {
      message.info('该类型不支持预览，请直接下载');
      return;
    }
    setPreview({ path: joinPath(item.name), name: item.name, size: item.size });
  };

  if (sources.loaded && !ds) {
    return (
      <Card>
        <Typography.Text type="danger">数据源不存在</Typography.Text>
      </Card>
    );
  }

  return (
    <Card
      title={
        <Space>
          <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/')} />
          <span>{ds?.name ?? '…'}</span>
        </Space>
      }
      extra={
        <Space>
          <Upload
            multiple
            showUploadList={false}
            beforeUpload={(file, fileList) => {
              // beforeUpload 每个文件回调一次；只在首个文件时入队整批
              if (file === fileList[0]) enqueueUploads(fileList as unknown as File[]);
              return false;
            }}
          >
            <Button type="primary" icon={<UploadOutlined />}>
              上传文件
            </Button>
          </Upload>
          <Upload
            directory
            showUploadList={false}
            beforeUpload={(file, fileList) => {
              // beforeUpload 每个文件回调一次；只在首个文件时入队整批
              if (file === fileList[0]) enqueueUploads(fileList as unknown as File[]);
              return false;
            }}
          >
            <Button icon={<UploadOutlined />}>上传文件夹</Button>
          </Upload>
          <Button icon={<FolderAddOutlined />} onClick={newFolderAction}>
            新建目录
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => void refresh()} />
        </Space>
      }
    >
      <Breadcrumb
        style={{ marginBottom: 12 }}
        items={[
          {
            title: <a onClick={() => setStack([])}>根目录</a>,
          },
          ...stack.map((name, i) => ({
            title:
              i === stack.length - 1 ? (
                <span>{name}</span>
              ) : (
                <a onClick={() => setStack(stack.slice(0, i + 1))}>{name}</a>
              ),
          })),
        ]}
      />

      <Table<FsEntry>
        rowKey={(e) => `${e.foreign ? 'f' : 'm'}:${e.name}`}
        dataSource={entries}
        loading={loading}
        pagination={false}
        size="middle"
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
            title: '操作',
            key: 'ops',
            width: 220,
            render: (_, item) =>
              item.foreign ? (
                <Button
                  size="small"
                  danger
                  icon={<DeleteOutlined />}
                  onClick={() => deleteForeignAction(item)}
                />
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
  );
}
