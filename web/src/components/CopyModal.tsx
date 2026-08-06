import { FolderOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { Alert, App, Breadcrumb, Checkbox, Empty, Modal, Select, Spin, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { api, type CopyReport, type FsEntry } from '../api/client';
import { useSources } from '../stores/sources';
import { taskNote, taskProgress, taskUploaded, useTasks } from '../stores/tasks';
import { formatBytes } from '../utils/format';

const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);

const MODE_LABEL: Record<CopyReport['mode'], string> = {
  rapid: '秒传',
  transfer: '普通传输',
  mixed: '秒传 + 普通传输',
  empty: '无内容',
};

/** 把成绩单摊成一行人话：到底秒传了多少、又真搬了多少字节。 */
export function describeCopy(report: CopyReport): string {
  const parts = [MODE_LABEL[report.mode]];
  if (report.rapidVolumes) parts.push(`秒传 ${report.rapidVolumes} 卷 ${formatBytes(report.rapidBytes)}`);
  if (report.transferredVolumes)
    parts.push(`实传 ${report.transferredVolumes} 卷 ${formatBytes(report.transferredBytes)}`);
  if (report.reencryptedFiles) parts.push(`重新编码 ${report.reencryptedFiles} 个文件`);
  if (report.skipped.length) parts.push(`跳过 ${report.skipped.length} 项`);
  return parts.join(' · ');
}

/**
 * 复制到…（可跨数据源）：选目标数据源 + 目标目录，逐项排进传输队列。
 *
 * 两端加密开关一致时服务端按分卷原样搬运密文，网盘支持就直接秒传；不一致
 * 只能解密再重新加密。任务完成后把实际走的路子写进任务备注与提示。
 */
export default function CopyModal({
  dsId,
  sourceDir,
  items,
  onClose,
  onCopied,
}: {
  dsId: string;
  /** 待复制条目所在的明文目录（"" = 根） */
  sourceDir: string;
  /** 待复制条目（名字 + 大小，大小仅用于进度条） */
  items: { name: string; size: number; isDir: boolean }[];
  onClose: () => void;
  /** 复制完成后回调（目标就是当前目录时需要刷新列表） */
  onCopied: () => void;
}) {
  const { message } = App.useApp();
  const sources = useSources();
  const enqueue = useTasks((s) => s.enqueue);
  const [destDs, setDestDs] = useState(dsId);
  const [path, setPath] = useState(sourceDir);
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [overwrite, setOverwrite] = useState(false);

  const src = sources.list.find((d) => d.id === dsId);
  const dest = sources.list.find((d) => d.id === destDs);

  useEffect(() => {
    let stale = false;
    setLoading(true);
    api
      .listFiles(destDs, path)
      .then((list) => {
        if (!stale) setEntries(list);
      })
      .catch((e) => message.error(e instanceof Error ? e.message : String(e)))
      .finally(() => {
        if (!stale) setLoading(false);
      });
    return () => {
      stale = true;
    };
  }, [destDs, path, message]);

  const stack = useMemo(() => (path ? path.split('/') : []), [path]);
  const copied = useMemo(() => new Set(items.map((i) => i.name)), [items]);
  const sameDir = destDs === dsId && path === sourceDir;
  // 同源同目录下，正在复制的目录自身不能作为目标（会复制进自己）
  const dirs = entries.filter(
    (e) => e.isDir && !e.foreign && !(destDs === dsId && path === sourceDir && copied.has(e.name)),
  );

  const switchDs = (id: string) => {
    setDestDs(id);
    setPath(id === dsId ? sourceDir : '');
  };

  const onOk = () => {
    const destName = dest?.name ?? destDs;
    for (const item of items) {
      const id = crypto.randomUUID();
      const from = join(sourceDir, item.name);
      const to = join(path, item.name);
      enqueue(
        { id, kind: 'copy', name: `${item.name} → ${destName}`, dsName: destName, totalBytes: item.size },
        async () => {
          // 服务端按 progress id 记双维度进度：读出的密文 / 目标已确认写入。
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
            const report = await api.copyPath(dsId, from, destDs, to, { overwrite, progress: id });
            const detail = describeCopy(report);
            taskNote(id, detail);
            message.success(`${item.name} → ${destName}：${detail}`);
          } finally {
            window.clearInterval(poll);
          }
          onCopied();
        },
      );
    }
    message.info(`已加入传输队列 ${items.length} 项，完成后可在传输队列查看是否走了秒传`);
    onClose();
  };

  const mismatch = !!src && !!dest && src.encryptionEnabled !== dest.encryptionEnabled;

  return (
    <Modal
      open
      title={`复制 ${items.length} 项到…`}
      okText="复制到此处"
      okButtonProps={{ disabled: sameDir || loading }}
      onOk={onOk}
      onCancel={onClose}
    >
      <Select
        style={{ width: '100%', marginBottom: 10 }}
        value={destDs}
        onChange={switchDs}
        options={sources.list.map((d) => ({
          label: d.id === dsId ? `${d.name}（当前数据源）` : d.name,
          value: d.id,
        }))}
      />
      <Alert
        style={{ marginBottom: 10 }}
        type={mismatch ? 'warning' : 'info'}
        showIcon
        icon={<ThunderboltOutlined />}
        message={
          mismatch
            ? '两端加密设置不同，只能解密后重新加密传输，无法秒传。'
            : '两端加密设置一致，将按分卷原样搬运密文；目标网盘支持时自动秒传。'
        }
      />
      <Breadcrumb
        style={{ marginBottom: 10 }}
        items={[
          {
            title: stack.length === 0 ? <span>根目录</span> : <a onClick={() => setPath('')}>根目录</a>,
          },
          ...stack.map((name, i) => ({
            title:
              i === stack.length - 1 ? (
                <span>{name}</span>
              ) : (
                <a onClick={() => setPath(stack.slice(0, i + 1).join('/'))}>{name}</a>
              ),
          })),
        ]}
      />
      <Spin spinning={loading}>
        <div className="move-dir-list">
          {dirs.length === 0 ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="没有子目录"
              style={{ padding: '24px 0' }}
            />
          ) : (
            dirs.map((d) => (
              <div key={d.name} className="move-dir-item" onClick={() => setPath(join(path, d.name))}>
                <FolderOutlined style={{ color: '#faad14' }} />
                <span>{d.name}</span>
              </div>
            ))
          )}
        </div>
      </Spin>
      <Checkbox
        style={{ marginTop: 10 }}
        checked={overwrite}
        onChange={(e) => setOverwrite(e.target.checked)}
      >
        覆盖目标已存在的同名条目
      </Checkbox>
      {sameDir && (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            当前就是源目录，请换个数据源或进入其他目录。
          </Typography.Text>
        </div>
      )}
    </Modal>
  );
}
