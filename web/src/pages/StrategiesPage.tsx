import { App, Button, Card, Checkbox, Form, Input, Modal, Space, Table, Typography } from 'antd';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { api, type Strategy } from '../api/client';
import { useSources } from '../stores/sources';
import { formatBytes, formatTime, parseSize, sizeToInput } from '../utils/format';

interface FormValues {
  name: string;
  /** 分卷大小字符串："300M"、"1.5GB"、"512K" */
  volumeText: string;
  noVolume: boolean;
  password: string;
}

/** 数据映射策略 = 根密码 + 分卷大小。根密码是该策略下所有数据源的解密入口。 */
export default function StrategiesPage() {
  const { message, modal } = App.useApp();
  const sources = useSources();
  const [list, setList] = useState<Strategy[]>([]);
  const [editing, setEditing] = useState<Strategy | null>(null);
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<FormValues>();

  const refresh = useCallback(async () => {
    setList(await api.listStrategies());
  }, []);

  useEffect(() => {
    void refresh().catch((e: unknown) =>
      message.error(e instanceof Error ? e.message : String(e)),
    );
    void sources.refresh().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const boundIds = useMemo(() => new Set(sources.list.map((d) => d.strategyId)), [sources.list]);

  const openCreate = () => {
    setEditing(null);
    form.setFieldsValue({ name: '', volumeText: '300M', noVolume: false, password: '' });
    setOpen(true);
  };

  const openEdit = (s: Strategy) => {
    setEditing(s);
    form.setFieldsValue({
      name: s.name,
      volumeText: s.volumeSize == null ? '300M' : sizeToInput(s.volumeSize),
      noVolume: s.volumeSize == null,
      password: s.password,
    });
    setOpen(true);
  };

  const onSubmit = async () => {
    const raw = await form.validateFields();
    const values = {
      name: raw.name,
      volumeSize: raw.noVolume ? null : parseSize(raw.volumeText),
      password: raw.password || undefined,
    };
    try {
      if (editing) {
        const passwordChanged = values.password !== editing.password;
        if (passwordChanged) {
          const confirmed = await new Promise<boolean>((resolve) => {
            modal.confirm({
              title: '确认更换根密码？',
              content:
                '将在线迁移该策略下所有数据源的根层加密名（子目录与文件内容不动）。' +
                '迁移期间数据保持可读；若中断（如网络故障），重新保存一次即可续传。' +
                '改回旧密码可完全还原。',
              okType: 'danger',
              onOk: () => resolve(true),
              onCancel: () => resolve(false),
            });
          });
          if (!confirmed) return;
        }
        await api.updateStrategy(editing.id, values);
        message.success(
          passwordChanged
            ? '根密码已更换，云端根层名称迁移完成'
            : '策略已更新（分卷大小仅影响之后上传的文件）',
        );
      } else {
        await api.createStrategy(values);
        message.success('策略已创建，请立即备份根密码');
      }
      setOpen(false);
      await refresh();
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
    }
  };

  const onDelete = (s: Strategy) => {
    if (boundIds.has(s.id)) {
      message.warning('策略正被数据源使用，无法删除');
      return;
    }
    modal.confirm({
      title: `删除策略「${s.name}」？`,
      onOk: async () => {
        await api.deleteStrategy(s.id);
        message.success('已删除');
        await refresh();
      },
    });
  };

  return (
    <Card
      title="数据映射策略"
      extra={
        <Button type="primary" onClick={openCreate}>
          新建策略
        </Button>
      }
    >
      <Table
        rowKey="id"
        dataSource={list}
        pagination={false}
        columns={[
          { title: '名称', dataIndex: 'name' },
          {
            title: '上传分卷大小',
            dataIndex: 'volumeSize',
            render: (v: number | null) => (v == null ? '不分卷' : formatBytes(v)),
          },
          {
            title: '根密码',
            dataIndex: 'password',
            render: (v: string) => (
              <Typography.Text copyable={{ text: v, tooltips: ['复制根密码', '已复制'] }}>
                ••••••••
              </Typography.Text>
            ),
          },
          {
            title: '状态',
            key: 'state',
            render: (_: unknown, s: Strategy) =>
              boundIds.has(s.id) ? '使用中' : '未绑定',
          },
          {
            title: '创建时间',
            dataIndex: 'createdAt',
            render: (v: number) => formatTime(v),
          },
          {
            title: '操作',
            key: 'ops',
            render: (_: unknown, s: Strategy) => (
              <Space>
                <Button size="small" onClick={() => openEdit(s)}>
                  编辑
                </Button>
                <Button size="small" danger disabled={boundIds.has(s.id)} onClick={() => onDelete(s)}>
                  删除
                </Button>
              </Space>
            ),
          },
        ]}
      />

      <Modal
        title={editing ? '编辑策略' : '新建策略'}
        open={open}
        onOk={() => void onSubmit()}
        onCancel={() => setOpen(false)}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" name="strategy">
          <Form.Item name="name" label="策略名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="如：默认策略" />
          </Form.Item>
          <Form.Item name="noVolume" valuePropName="checked" style={{ marginBottom: 8 }}>
            <Checkbox>不分卷（整个文件一个分卷，云端可见真实大小）</Checkbox>
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(a, b) => a.noVolume !== b.noVolume}>
            {({ getFieldValue }) =>
              !getFieldValue('noVolume') && (
                <Form.Item
                  name="volumeText"
                  label="上传分卷大小"
                  tooltip="一个文件在云端被切成若干这么大的密文分卷；支持 K/KB/M/MB/G/GB 单位，如 300M、1.5GB；至少 64KB"
                  rules={[
                    { required: true, message: '请输入分卷大小' },
                    {
                      validator: (_r, v: string) => {
                        const n = parseSize(v ?? '');
                        if (n == null) return Promise.reject(new Error('格式如 300M / 1.5GB / 512K'));
                        if (n < 64 * 1024) return Promise.reject(new Error('至少 64KB'));
                        return Promise.resolve();
                      },
                    },
                  ]}
                >
                  <Input placeholder="300M" style={{ width: '100%' }} />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item
            name="password"
            label="根密码"
            tooltip="该策略下所有数据源的解密入口；留空自动生成随机密码。丢失 = 数据永久无法解密！"
          >
            <Input.Password placeholder="留空自动生成" autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
