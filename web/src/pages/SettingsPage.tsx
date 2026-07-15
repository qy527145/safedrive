import { App, Button, Card, Checkbox, Form, Input, InputNumber, Space, Statistic, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { api, type CacheStats, type TransferSettings } from '../api/client';
import { formatBytes, parseSize, sizeToInput } from '../utils/format';

/** 设置：全局传输参数 + 数据源根密钥的备份导出 / 导入合并。 */
export default function SettingsPage() {
  const { message, modal } = App.useApp();
  const [form] = Form.useForm<{
    maxSplit: string;
    maxThreads: number;
    maxPerVolume: number;
    cacheEnabled: boolean;
  }>();
  const [saving, setSaving] = useState(false);
  const [cacheStats, setCacheStats] = useState<CacheStats>();

  useEffect(() => {
    api
      .getSettings()
      .then((s) => form.setFieldsValue({ ...s, maxSplit: sizeToInput(s.maxSplit) }))
      .catch((e: unknown) => message.error(e instanceof Error ? e.message : String(e)));
    void api.getCacheStats().then(setCacheStats).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveSettings = async () => {
    const raw = await form.validateFields();
    const values: TransferSettings = {
      maxThreads: raw.maxThreads,
      maxPerVolume: raw.maxPerVolume,
      maxSplit: parseSize(raw.maxSplit) ?? 0,
      cacheEnabled: raw.cacheEnabled,
    };
    setSaving(true);
    try {
      await api.updateSettings(values);
      message.success('传输设置已保存（立即对后续下载生效）');
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (<>
    <div className="page-heading"><div><span className="page-kicker">SYSTEM CONTROL</span><h1>系统设置</h1>
      <p>调整传输并发、缓存策略与服务端数据处理行为。</p></div></div>
    <Space className="settings-grid" direction="vertical" size="large">
      <Card title="传输设置">
        <Typography.Paragraph type="secondary">
          全局下载并发参数对所有数据源生效；加密、分卷和数据源级缓存请在“数据源管理”中配置。
        </Typography.Paragraph>
        <Form form={form} layout="vertical" name="transfer" style={{ maxWidth: 420 }}>
          <Form.Item
            name="maxSplit"
            label="最大分片大小"
            tooltip="下载时单线程一次拉取的分片上限（部分云盘 API 限制单请求最大字节数）；支持 K/KB/M/MB/G/GB 单位，默认 5M"
            rules={[
              { required: true, message: '请输入分片大小' },
              {
                validator: (_r, v: string) => {
                  const n = parseSize(v ?? '');
                  if (n == null) return Promise.reject(new Error('格式如 5M / 512K / 1.5GB'));
                  if (n < 64 * 1024) return Promise.reject(new Error('至少 64KB'));
                  return Promise.resolve();
                },
              },
            ]}
          >
            <Input placeholder="5M" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="maxThreads"
            label="下载线程数"
            tooltip="并行拉取云端分片的总并发数"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={128} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="maxPerVolume"
            label="单分卷最大并发线程数"
            tooltip="同一个分卷文件内的最大并发（部分服务器限制单文件连接数）"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={64} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="cacheEnabled" valuePropName="checked">
            <Checkbox>启用全局持久密文块缓存</Checkbox>
          </Form.Item>
          <Button type="primary" loading={saving} onClick={() => void saveSettings()}>
            保存
          </Button>
        </Form>
      </Card>

      <Card
        title="全局下载缓存"
        extra={
          <Button
            danger
            onClick={() =>
              modal.confirm({
                title: '清空全部下载缓存？',
                onOk: async () => {
                  const result = await api.clearCache();
                  message.success(`已清理 ${formatBytes(result.freed)}`);
                  setCacheStats(await api.getCacheStats());
                },
              })
            }
          >
            清空缓存
          </Button>
        }
      >
        <Space size="large" wrap>
          <Statistic title="缓存文件" value={cacheStats?.entries ?? 0} />
          <Statistic title="已缓存" value={formatBytes(cacheStats?.bytesCached ?? 0)} />
          <Statistic title="命中" value={cacheStats?.hits ?? 0} />
          <Statistic title="回源" value={cacheStats?.misses ?? 0} />
        </Space>
        <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
          缓存内容是云端密文，按 1 MiB 完整块持久化；分片重叠时只有真实覆盖整块才会标记命中。
        </Typography.Paragraph>
      </Card>

      <Card title="加密方案">
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          信封链（cryptree）：每个文件/目录持独立随机密钥，加密后藏在自身的
          云端名称里，由父目录密钥解开，层层下钻。启用加密时文件在云端是一个加密名文件夹 +
          若干密文分卷（ChaCha20，密文长=明文长，任意偏移可寻址）。加解密全部在
          服务端完成，云端始终只见密文；分享一个目录只需交出该目录的密钥。
        </Typography.Paragraph>
      </Card>
    </Space></>);
}
