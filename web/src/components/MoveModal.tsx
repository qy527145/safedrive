import { FolderOutlined } from '@ant-design/icons';
import { App, Breadcrumb, Empty, Modal, Spin, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { api, type FsEntry } from '../api/client';

const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);

/**
 * 批量移动的目标目录选择器：在同一数据源内逐层浏览目录，选定后逐项
 * 调用 rename（服务端 rename 即移动：换父钥重编码信封，内容零重加密）。
 */
export default function MoveModal({
  dsId,
  sourceDir,
  names,
  onClose,
  onMoved,
}: {
  dsId: string;
  /** 待移动条目所在的明文目录（"" = 根） */
  sourceDir: string;
  /** 待移动条目名（不含路径） */
  names: string[];
  onClose: () => void;
  /** 移动结束后回调（无论是否全部成功），父组件负责刷新列表 */
  onMoved: () => void;
}) {
  const { message, modal } = App.useApp();
  const [path, setPath] = useState(sourceDir);
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [moving, setMoving] = useState(false);

  useEffect(() => {
    let stale = false;
    setLoading(true);
    api
      .listFiles(dsId, path)
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
  }, [dsId, path, message]);

  const stack = useMemo(() => (path ? path.split('/') : []), [path]);
  // 只能进入受管目录；正在移动的文件夹自身不可进入（不能移动到自身或其子目录）
  const moved = useMemo(() => new Set(names), [names]);
  const dirs = entries.filter(
    (e) => e.isDir && !e.foreign && !(path === sourceDir && moved.has(e.name)),
  );

  const onOk = async () => {
    setMoving(true);
    const failed: string[] = [];
    let done = 0;
    try {
      // 逐项串行：网盘 API 有速率限制，且失败时能精确归因到条目
      for (const name of names) {
        try {
          await api.rename(dsId, join(sourceDir, name), join(path, name));
          done += 1;
        } catch (e) {
          failed.push(`${name}：${e instanceof Error ? e.message : String(e)}`);
        }
      }
    } finally {
      setMoving(false);
    }
    if (failed.length === 0) {
      message.success(`已移动 ${done} 项`);
    } else {
      modal.error({
        title: `${failed.length} 项移动失败${done ? `（${done} 项已成功）` : ''}`,
        content: (
          <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
            {failed.join('\n')}
          </Typography.Paragraph>
        ),
      });
    }
    onMoved();
    onClose();
  };

  return (
    <Modal
      open
      title={`移动 ${names.length} 项到…`}
      okText="移动到此处"
      okButtonProps={{ disabled: path === sourceDir || loading }}
      confirmLoading={moving}
      onOk={() => void onOk()}
      onCancel={onClose}
    >
      <Breadcrumb
        style={{ marginBottom: 10 }}
        items={[
          {
            title:
              stack.length === 0 ? (
                <span>根目录</span>
              ) : (
                <a onClick={() => setPath('')}>根目录</a>
              ),
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
              <div
                key={d.name}
                className="move-dir-item"
                onClick={() => setPath(join(path, d.name))}
              >
                <FolderOutlined style={{ color: '#faad14' }} />
                <span>{d.name}</span>
              </div>
            ))
          )}
        </div>
      </Spin>
      {path === sourceDir && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          当前就在原目录，请进入其他目录后再确认移动。
        </Typography.Text>
      )}
    </Modal>
  );
}
