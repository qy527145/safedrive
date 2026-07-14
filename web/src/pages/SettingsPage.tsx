import { DownloadOutlined, ImportOutlined } from '@ant-design/icons';
import { App, Button, Card, Form, Input, InputNumber, Space, Typography, Upload } from 'antd';
import { useEffect, useState } from 'react';
import { api, getToken, type TransferSettings } from '../api/client';
import { parseSize, sizeToInput } from '../utils/format';

/** 设置：全局传输参数 + 数据源根密钥的备份导出 / 导入合并。 */
export default function SettingsPage() {
  const { message } = App.useApp();
  const [form] = Form.useForm<{ maxSplit: string; maxThreads: number; maxPerVolume: number }>();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => form.setFieldsValue({ ...s, maxSplit: sizeToInput(s.maxSplit) }))
      .catch((e: unknown) => message.error(e instanceof Error ? e.message : String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveSettings = async () => {
    const raw = await form.validateFields();
    const values: TransferSettings = {
      maxThreads: raw.maxThreads,
      maxPerVolume: raw.maxPerVolume,
      maxSplit: parseSize(raw.maxSplit) ?? 0,
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

  const exportVault = async () => {
    // 带上 token 走同源下载（服务端返回 attachment）
    const resp = await fetch('/api/vault/export', {
      headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
    });
    if (!resp.ok) {
      message.error(`导出失败 (${resp.status})`);
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const d = new Date();
    const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
    a.href = url;
    a.download = `safedrive-strategies-${stamp}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    message.success('已导出。注意：该文件含明文根密码，请妥善保管！');
  };

  return (
    <Space direction="vertical" size="large" style={{ width: '100%', maxWidth: 720 }}>
      <Card title="传输设置">
        <Typography.Paragraph type="secondary">
          全局下载参数（对所有数据源生效）；上传分卷大小属于各映射策略。
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
          <Button type="primary" loading={saving} onClick={() => void saveSettings()}>
            保存
          </Button>
        </Form>
      </Card>

      <Card title="策略备份（含根密码）">
        <Typography.Paragraph type="secondary">
          根密码在策略中（服务端 strategies.json）；各文件/目录的密钥加密后
          藏在云端文件名里，云端数据 + 根密码即可完整恢复。
          <Typography.Text strong type="danger">
            根密码丢失 = 该策略下云端数据永久无法解密
          </Typography.Text>
          。创建策略后请立即导出备份（文件为明文，请妥善保管）。
        </Typography.Paragraph>
        <Space>
          <Button type="primary" icon={<DownloadOutlined />} onClick={() => void exportVault()}>
            导出策略备份
          </Button>
          <Upload
            accept=".json"
            showUploadList={false}
            beforeUpload={async (file) => {
              try {
                const text = await file.text();
                JSON.parse(text); // 只做基本格式校验，结构由服务端验证
                const r = await api.vaultImport(text);
                message.success(`导入合并完成，新增 ${r.added} 条（冲突保留本地）`);
              } catch (e) {
                message.error(e instanceof Error ? e.message : '不是有效的密码本文件');
              }
              return false;
            }}
          >
            <Button icon={<ImportOutlined />}>导入并合并</Button>
          </Upload>
        </Space>
      </Card>

      <Card title="加密方案">
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          信封链（cryptree）：每个文件/目录持独立随机密钥，加密后藏在自身的
          云端名称里，由父目录密钥解开，层层下钻。文件在云端是一个加密名文件夹 +
          若干密文分卷（ChaCha20，密文长=明文长，任意偏移可寻址）。加解密全部在
          服务端完成，云端始终只见密文；分享一个目录只需交出该目录的密钥。
        </Typography.Paragraph>
      </Card>
    </Space>
  );
}
