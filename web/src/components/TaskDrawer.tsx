import {
  ClearOutlined,
  CloseOutlined,
  CopyOutlined,
  DownloadOutlined,
  ReloadOutlined,
  UploadOutlined,
} from '@ant-design/icons';
import { Button, Drawer, Empty, List, Progress, Space, Tag, Typography } from 'antd';
import { useTasks, type TransferTask } from '../stores/tasks';
import { formatBytes } from '../utils/format';

function statusTag(t: TransferTask) {
  switch (t.status) {
    case 'queued':
      return <Tag>排队中</Tag>;
    case 'running':
      return <Tag color="processing">进行中</Tag>;
    case 'done':
      return <Tag color="success">完成</Tag>;
    case 'error':
      return <Tag color="error">失败</Tag>;
    case 'canceled':
      return <Tag color="warning">已取消</Tag>;
  }
}

/** 上传/下载/跨源复制任务队列抽屉。 */
export default function TaskDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const tasks = useTasks((s) => s.tasks);
  const cancel = useTasks((s) => s.cancel);
  const retry = useTasks((s) => s.retry);
  const clearFinished = useTasks((s) => s.clearFinished);

  return (
    <Drawer
      title="传输队列"
      open={open}
      onClose={onClose}
      width={420}
      extra={
        <Button size="small" icon={<ClearOutlined />} onClick={clearFinished}>
          清除已完成
        </Button>
      }
    >
      {tasks.length === 0 ? (
        <Empty description="暂无任务" />
      ) : (
        <List
          dataSource={[...tasks].reverse()}
          renderItem={(t) => {
            const pct = (n: number) =>
              t.totalBytes > 0
                ? Math.min(100, Math.round((n / t.totalBytes) * 100))
                : t.status === 'done'
                  ? 100
                  : 0;
            const donePercent = pct(t.doneBytes);
            const uploadedPercent = pct(t.uploadedBytes);
            const dual = t.kind === 'upload' || t.kind === 'copy';
            return (
              <List.Item
                actions={
                  // 跨源复制在服务端一气呵成，中途没有可安全中断的点，不给取消
                  (t.status === 'running' || t.status === 'queued') && t.kind !== 'copy'
                    ? [<Button key="c" size="small" icon={<CloseOutlined />} onClick={() => cancel(t.id)} />]
                    : t.status === 'error'
                      ? [
                          <Button key="r" size="small" icon={<ReloadOutlined />} onClick={() => retry(t.id)}>
                            重试
                          </Button>,
                        ]
                      : []
                }
              >
                <List.Item.Meta
                  avatar={t.kind === 'upload' ? <UploadOutlined /> : t.kind === 'copy' ? <CopyOutlined /> : <DownloadOutlined />}
                  title={
                    <Space>
                      <Typography.Text style={{ maxWidth: 200 }} ellipsis>
                        {t.name}
                      </Typography.Text>
                      {statusTag(t)}
                    </Space>
                  }
                  description={
                    <>
                      <Progress
                        percent={donePercent}
                        // 上传/复制双维度同条呈现：绿 = 远端已确认，蓝 = 本地已就绪待传
                        success={dual ? { percent: uploadedPercent } : undefined}
                        size="small"
                        status={t.status === 'error' ? 'exception' : t.status === 'done' ? 'success' : 'active'}
                      />
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t.dsName} ·{' '}
                        {dual ? (
                          <>
                            <span style={{ color: '#1677ff' }}>
                              {t.kind === 'copy' ? '读取' : '加密'} {formatBytes(t.doneBytes)}
                            </span>{' '}
                            ·{' '}
                            <span style={{ color: '#52c41a' }}>写入 {formatBytes(t.uploadedBytes)}</span>
                            {t.totalBytes > 0 ? ` / ${formatBytes(t.totalBytes)}` : ''}
                          </>
                        ) : (
                          <>
                            {formatBytes(t.doneBytes)} / {formatBytes(t.totalBytes)}
                          </>
                        )}
                        {t.note ? ` · ${t.note}` : ''}
                        {t.error ? ` · ${t.error}` : ''}
                      </Typography.Text>
                    </>
                  }
                />
              </List.Item>
            );
          }}
        />
      )}
    </Drawer>
  );
}
