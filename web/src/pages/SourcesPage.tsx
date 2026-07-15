import { App, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { api, type DsRecord, type Strategy } from '../api/client';
import { useSources } from '../stores/sources';
import { formatTime } from '../utils/format';

interface FormValues {
  name: string;
  type: 'localfs' | 'webdav' | 'baidupan';
  strategyId: string;
  root?: string;
  url?: string;
  username?: string;
  password?: string;
  cookie?: string;
  userAgent?: string;
}

/** 数据源管理：基础信息（由类型决定）+ 绑定数据映射策略。 */
export default function SourcesPage() {
  const { message, modal } = App.useApp();
  const sources = useSources();
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DsRecord | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm<FormValues>();
  const [dsType, setDsType] = useState<'localfs' | 'webdav' | 'baidupan'>('localfs');

  useEffect(() => {
    void sources.refresh().catch((e: unknown) => message.error(String(e)));
    void api.listStrategies().then(setStrategies).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const strategyName = (id: string) => strategies.find((s) => s.id === id)?.name;

  const openCreate = () => {
    if (strategies.length === 0) {
      message.warning('请先在「策略管理」中创建一个数据映射策略');
      return;
    }
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ type: 'localfs', strategyId: strategies[0]?.id });
    setDsType('localfs');
    setOpen(true);
  };

  const openEdit = (d: DsRecord) => {
    setEditing(d);
    form.setFieldsValue({
      name: d.name,
      type: d.type,
      strategyId: d.strategyId,
      root: d.config.root,
      url: d.config.url,
      username: d.config.username,
      password: d.config.password,
      cookie: d.config.cookie,
      userAgent: d.config.userAgent,
    });
    setDsType(d.type);
    setOpen(true);
  };

  const onSubmit = async () => {
    const v = await form.validateFields();
    const config: Record<string, string> =
      v.type === 'localfs'
        ? { root: v.root ?? '' }
        : v.type === 'webdav'
          ? { url: v.url ?? '', username: v.username ?? '', password: v.password ?? '' }
          : { root: v.root ?? '/safedrive', cookie: v.cookie ?? '', userAgent: v.userAgent ?? '' };
    const body = { name: v.name, type: v.type, config, strategyId: v.strategyId };
    setSaving(true);
    try {
      const saved = editing ? await api.updateDs(editing.id, body) : await api.createDs(body);
      await sources.refresh();
      setOpen(false);
      // 保存后立即测试连接
      try {
        const r = await api.testDs(saved.id);
        message.success(`已保存，连接正常（根目录 ${r.entries} 个条目）`);
      } catch (e) {
        message.warning(`已保存，但连接测试失败：${e instanceof Error ? e.message : e}`);
      }
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const onTest = async (d: DsRecord) => {
    try {
      const r = await api.testDs(d.id);
      message.success(`连接正常（根目录 ${r.entries} 个条目）`);
    } catch (e) {
      message.error(`连接失败：${e instanceof Error ? e.message : e}`);
    }
  };

  const onDelete = (d: DsRecord) => {
    modal.confirm({
      title: `删除数据源「${d.name}」？`,
      content: '仅删除连接配置，云端密文数据不会被删除。',
      okButtonProps: { danger: true },
      onOk: async () => {
        await api.deleteDs(d.id);
        await sources.refresh();
      },
    });
  };

  return (
    <Card
      title="数据源管理"
      extra={
        <Button type="primary" onClick={openCreate}>
          添加数据源
        </Button>
      }
    >
      <Typography.Paragraph type="secondary">
        连接信息与策略保存在服务端；每个文件的密钥由服务端密码本管理（请在「设置」页定期备份）。
      </Typography.Paragraph>
      <Table<DsRecord>
        rowKey="id"
        dataSource={sources.list}
        loading={!sources.loaded}
        pagination={false}
        columns={[
          { title: '名称', dataIndex: 'name' },
          {
            title: '类型',
            dataIndex: 'type',
            render: (t: string) =>
              t === 'localfs' ? (
                <Tag color="geekblue">本地文件系统</Tag>
              ) : t === 'webdav' ? (
                <Tag color="cyan">WebDAV</Tag>
              ) : (
                <Tag color="blue">百度网盘</Tag>
              ),
          },
          {
            title: '位置',
            key: 'loc',
            render: (_, d) => (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {d.type === 'webdav' ? d.config.url : d.config.root}
              </Typography.Text>
            ),
          },
          {
            title: '映射策略',
            dataIndex: 'strategyId',
            render: (id: string) =>
              strategyName(id) ? (
                <Tag color="purple">{strategyName(id)}</Tag>
              ) : (
                <Tag color="error">策略缺失</Tag>
              ),
          },
          { title: '创建时间', dataIndex: 'createdAt', render: (v: number) => formatTime(v) },
          {
            title: '操作',
            key: 'actions',
            render: (_, d) => (
              <Space>
                <Button size="small" onClick={() => void onTest(d)}>
                  测试
                </Button>
                <Button size="small" onClick={() => openEdit(d)}>
                  编辑
                </Button>
                <Button size="small" danger onClick={() => onDelete(d)}>
                  删除
                </Button>
              </Space>
            ),
          },
        ]}
      />

      <Modal
        title={editing ? '编辑数据源' : '添加数据源'}
        open={open}
        confirmLoading={saving}
        onOk={() => void onSubmit()}
        onCancel={() => setOpen(false)}
        destroyOnHidden
      >
        <Form form={form} name="ds" layout="vertical">
          <Form.Item name="name" label="数据源名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="如：家庭 NAS / 坚果云" />
          </Form.Item>
          <Form.Item name="type" label="类型" rules={[{ required: true }]}>
            <Select
              disabled={!!editing}
              onChange={(v: 'localfs' | 'webdav' | 'baidupan') => setDsType(v)}
              options={[
                { label: '本地文件系统（服务器磁盘目录）', value: 'localfs' },
                { label: 'WebDAV', value: 'webdav' },
                { label: '百度网盘（Cookie）', value: 'baidupan' },
              ]}
            />
          </Form.Item>
          {dsType === 'localfs' && (
            <Form.Item
              name="root"
              label="根目录（服务器上的绝对路径，不存在时自动创建）"
              rules={[{ required: true, message: '请输入根目录' }]}
            >
              <Input placeholder="/data/safedrive" />
            </Form.Item>
          )}
          {dsType === 'webdav' && (
            <>
              <Form.Item
                name="url"
                label="WebDAV 地址"
                rules={[
                  { required: true, message: '请输入地址' },
                  { pattern: /^https?:\/\//, message: '必须以 http(s):// 开头' },
                ]}
              >
                <Input placeholder="https://dav.example.com/dav" />
              </Form.Item>
              <Form.Item name="username" label="用户名">
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="password" label="密码（保存在服务端配置中）">
                <Input.Password autoComplete="new-password" />
              </Form.Item>
            </>
          )}
          {dsType === 'baidupan' && (
            <>
              <Form.Item
                name="root"
                label="网盘根目录"
                initialValue="/safedrive"
                rules={[{ required: true, message: '请输入网盘根目录' }]}
                extra="连接测试时若目录不存在会自动创建；建议使用独立目录"
              >
                <Input placeholder="/safedrive" />
              </Form.Item>
              <Form.Item
                name="cookie"
                label="百度网盘 Cookie"
                rules={[
                  { required: true, message: '请输入 Cookie' },
                  { pattern: /(?:^|;\s*)BDUSS=/, message: 'Cookie 必须包含 BDUSS' },
                ]}
                extra="从 pan.baidu.com 已登录请求中复制完整 Cookie；凭证将保存在服务端配置中"
              >
                <Input.TextArea autoComplete="off" rows={4} placeholder="BDUSS=...; STOKEN=...; BAIDUID=..." />
              </Form.Item>
              <Form.Item name="userAgent" label="下载 User-Agent（留空使用 Android 网盘 UA）">
                <Input autoComplete="off" placeholder="netdisk;P2SP;2.2.61.31;android" />
              </Form.Item>
            </>
          )}
          <Form.Item
            name="strategyId"
            label="数据映射策略"
            rules={[{ required: true, message: '请选择策略' }]}
            extra="策略只含分卷与下载传输参数，随时可换，不影响已上传的数据"
          >
            <Select options={strategies.map((s) => ({ label: s.name, value: s.id }))} />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
