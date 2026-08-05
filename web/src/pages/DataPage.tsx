import {
  ApiOutlined, AppstoreOutlined, BarsOutlined, CopyOutlined, DatabaseOutlined, DeleteOutlined,
  ImportOutlined, LinkOutlined, MoreOutlined, PlusOutlined, SearchOutlined,
} from '@ant-design/icons';
import {
  App, Button, Card, Checkbox, Col, Dropdown, Empty, Input, Row, Segmented, Select, Skeleton, Space,
  Table, Tag, Typography, type MenuProps,
} from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type DsRecord, type DsType } from '../api/client';
import SourceModal from '../components/SourceModal';
import { useSources } from '../stores/sources';
import { formatTime } from '../utils/format';

/** 数据源类型的展示标签与配色，筛选下拉与类型标签共用一份。 */
const DS_TYPE_META: Record<DsType, { label: string; color: string }> = {
  localfs: { label: '本地文件系统', color: 'geekblue' },
  webdav: { label: 'WebDAV', color: 'cyan' },
  baidupan: { label: '百度网盘', color: 'blue' },
  aliyundrive: { label: '阿里云盘', color: 'orange' },
  quark: { label: '夸克网盘', color: 'purple' },
};

/** 数据管理首页：数据源入口（卡片/列表两种呈现）+ 添加/编辑/克隆/分享/批量管理。 */
export default function DataPage() {
  const { message, modal } = App.useApp();
  const sources = useSources();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DsRecord | null>(null);
  const [cloneFrom, setCloneFrom] = useState<DsRecord | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [batchTesting, setBatchTesting] = useState(false);
  // 呈现方式：卡片 / 列表，记忆在本地
  const [view, setView] = useState<'card' | 'list'>(() =>
    localStorage.getItem('sd.view.sources') === 'list' ? 'list' : 'card',
  );
  const changeView = (v: 'card' | 'list') => {
    setView(v);
    localStorage.setItem('sd.view.sources', v);
  };
  // 顶部筛选：按名称搜索 + 按类型过滤（数据源多了便于快速定位）
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<DsType | 'all'>('all');
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sources.list.filter(
      (d) =>
        (typeFilter === 'all' || d.type === typeFilter) &&
        (!q || d.name.toLowerCase().includes(q)),
    );
  }, [sources.list, query, typeFilter]);

  useEffect(() => {
    void sources.refresh().catch((e: unknown) => message.error(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 列表刷新后清掉已不存在的选中项（例如批量删除后）
  useEffect(() => {
    setSelectedIds((cur) => cur.filter((id) => sources.list.some((d) => d.id === id)));
  }, [sources.list]);

  const openCreate = () => { setEditing(null); setCloneFrom(null); setOpen(true); };
  const openEdit = (d: DsRecord) => { setEditing(d); setCloneFrom(null); setOpen(true); };
  /** 克隆：以现有数据源为模板打开新建弹窗，微调后保存为新数据源。 */
  const openClone = (d: DsRecord) => { setEditing(null); setCloneFrom(d); setOpen(true); };
  const onTest = (d: DsRecord) => void api.testDs(d.id)
    .then((r) => message.success(`连接正常（${r.entries} 个条目）`))
    .catch((e: unknown) => message.error(String(e)));
  const onDelete = (d: DsRecord) => modal.confirm({
    title: `删除数据源「${d.name}」？`,
    content: '只删除连接配置，不删除远端数据。',
    okButtonProps: { danger: true },
    onOk: async () => { await api.deleteDs(d.id); await sources.refresh(); },
  });

  /** 生成 sdds:// 配置分享链接：链接本身就是凭证，只应发给可信接收者。 */
  const onShare = async (d: DsRecord) => {
    let link: string;
    try {
      link = (await api.shareDs(d.id)).link;
    } catch (e) {
      message.error(e instanceof Error ? e.message : String(e));
      return;
    }
    modal.confirm({
      title: `分享数据源「${d.name}」`,
      icon: <LinkOutlined />,
      content: (
        <Space direction="vertical" style={{ width: '100%' }}>
          <Typography.Text type="warning">
            链接包含完整连接凭证与加密根密码，请只发给完全可信的设备或接收者。
          </Typography.Text>
          <Input.TextArea readOnly value={link} autoSize={{ minRows: 2, maxRows: 6 }} onFocus={(e) => e.target.select()} />
        </Space>
      ),
      okText: '复制链接',
      cancelText: '关闭',
      onOk: async () => {
        await navigator.clipboard.writeText(link);
        message.success('数据源分享链接已复制');
      },
    });
  };

  const importAction = () => {
    let link = '';
    modal.confirm({
      title: '通过链接导入数据源',
      icon: <ImportOutlined />,
      content: (
        <Input.TextArea
          autoSize={{ minRows: 3, maxRows: 6 }}
          placeholder="粘贴 sdds:// 数据源分享链接"
          onChange={(e) => { link = e.target.value; }}
        />
      ),
      okText: '导入',
      onOk: async () => {
        if (!link.trim()) throw new Error('请粘贴分享链接');
        try {
          const ds = await api.importDs(link.trim());
          await sources.refresh();
          message.success(`已导入数据源「${ds.name}」`);
        } catch (e) {
          message.error(e instanceof Error ? e.message : String(e));
          throw e; // 保留输入弹窗，便于更正后重试
        }
      },
    });
  };

  const selected = () => sources.list.filter((d) => selectedIds.includes(d.id));

  /** 批量测试：逐项串行测试选中数据源，汇总每项结果。 */
  const batchTestAction = async () => {
    const targets = selected();
    setBatchTesting(true);
    const lines: string[] = [];
    let ok = 0;
    for (const d of targets) {
      try {
        const r = await api.testDs(d.id);
        ok += 1;
        lines.push(`✓ ${d.name}：连接正常（${r.entries} 个条目）`);
      } catch (e) {
        lines.push(`✗ ${d.name}：${e instanceof Error ? e.message : String(e)}`);
      }
    }
    setBatchTesting(false);
    modal.info({
      title: `测试完成：${ok}/${targets.length} 连接正常`,
      content: (
        <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
          {lines.join('\n')}
        </Typography.Paragraph>
      ),
    });
  };

  /** 批量删除：逐项串行删除，失败的逐条归因，最后统一刷新。 */
  const batchDeleteAction = () => {
    const targets = selected();
    modal.confirm({
      title: `删除选中的 ${targets.length} 个数据源？`,
      content: '只删除连接配置，不删除远端数据。',
      okButtonProps: { danger: true },
      onOk: async () => {
        const failed: string[] = [];
        let done = 0;
        for (const d of targets) {
          try {
            await api.deleteDs(d.id);
            done += 1;
          } catch (e) {
            failed.push(`${d.name}：${e instanceof Error ? e.message : String(e)}`);
          }
        }
        if (failed.length === 0) {
          message.success(`已删除 ${done} 个数据源`);
        } else {
          modal.error({
            title: `${failed.length} 个删除失败${done ? `（${done} 个已成功）` : ''}`,
            content: (
              <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
                {failed.join('\n')}
              </Typography.Paragraph>
            ),
          });
        }
        await sources.refresh();
      },
    });
  };

  const toggleSelected = (id: string, checked: boolean) =>
    setSelectedIds((cur) => (checked ? [...cur, id] : cur.filter((v) => v !== id)));

  /** 低频操作收进「更多」菜单，避免每行五个按钮。 */
  const moreMenu = (d: DsRecord): MenuProps => ({
    items: [
      { key: 'clone', icon: <CopyOutlined />, label: '克隆' },
      { key: 'share', icon: <LinkOutlined />, label: '分享链接' },
      { type: 'divider' },
      { key: 'delete', icon: <DeleteOutlined />, danger: true, label: '删除' },
    ],
    onClick: ({ key, domEvent }) => {
      domEvent.stopPropagation();
      if (key === 'clone') openClone(d);
      else if (key === 'share') void onShare(d);
      else if (key === 'delete') onDelete(d);
    },
  });

  const modalNode = (
    <SourceModal
      open={open}
      editing={editing}
      cloneFrom={cloneFrom}
      onClose={() => setOpen(false)}
    />
  );
  const heading = (
    <PageHeading onAdd={openCreate} onImport={importAction} view={view} onViewChange={changeView} />
  );
  const batchBar = selectedIds.length > 0 && (
    <Space style={{ marginBottom: 12 }} wrap>
      <Typography.Text type="secondary">已选 {selectedIds.length} 项</Typography.Text>
      <Button size="small" icon={<ApiOutlined />} loading={batchTesting} onClick={() => void batchTestAction()}>
        测试
      </Button>
      <Button size="small" danger icon={<DeleteOutlined />} onClick={batchDeleteAction}>
        删除
      </Button>
      <Button size="small" type="text" onClick={() => setSelectedIds([])}>
        取消选择
      </Button>
    </Space>
  );
  const filterBar = (
    <div className="ds-toolbar">
      <Input
        className="ds-toolbar-search"
        prefix={<SearchOutlined />}
        allowClear
        placeholder="搜索数据源名称"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <Select<DsType | 'all'>
        className="ds-toolbar-type"
        value={typeFilter}
        onChange={setTypeFilter}
        popupMatchSelectWidth={false}
        options={[
          { value: 'all', label: '全部类型' },
          ...(Object.keys(DS_TYPE_META) as DsType[]).map((t) => ({
            value: t,
            label: DS_TYPE_META[t].label,
          })),
        ]}
      />
      {(query.trim() || typeFilter !== 'all') && (
        <span className="ds-toolbar-count">
          匹配 {filtered.length} / {sources.list.length}
        </span>
      )}
    </div>
  );
  const noMatch = <Empty description="没有匹配的数据源" />;

  if (!sources.loaded) return <>{heading}{modalNode}<Row gutter={[16,16]}>{[0,1,2].map((key) => <Col key={key} xs={24} sm={12} lg={8}><Card><Skeleton active avatar paragraph={{rows:2}} /></Card></Col>)}</Row></>;
  if (sources.list.length === 0) {
    return (
      <>{heading}{modalNode}<Card><Empty description="还没有数据源">
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            添加数据源
          </Button>
          <Button icon={<ImportOutlined />} onClick={importAction}>
            通过链接导入
          </Button>
        </Space>
      </Empty></Card></>
    );
  }

  const typeTag = (d: DsRecord) => {
    const tag = DS_TYPE_META[d.type];
    return <Tag color={tag.color}>{tag.label}</Tag>;
  };

  if (view === 'list') {
    return (
      <>{heading}{modalNode}<Card styles={{ body: { paddingTop: 16 } }}>
        {filterBar}
        {batchBar}
        <Table<DsRecord>
          rowKey="id"
          dataSource={filtered}
          pagination={false}
          size="middle"
          rowSelection={{
            selectedRowKeys: selectedIds,
            onChange: (keys) => setSelectedIds(keys.map(String)),
          }}
          columns={[
            {
              title: '名称',
              key: 'name',
              render: (_, d) => (
                <Space>
                  <span className="source-icon source-icon-sm"><DatabaseOutlined /></span>
                  <Typography.Link onClick={() => navigate(`/browse/${d.id}`)}>{d.name}</Typography.Link>
                </Space>
              ),
            },
            { title: '类型', key: 'type', width: 140, render: (_, d) => typeTag(d) },
            {
              title: '配置',
              key: 'config',
              render: (_, d) => (
                <>
                  <Tag color={d.encryptionEnabled ? 'green' : 'default'}>
                    {d.encryptionEnabled ? '已加密' : '未加密'}
                  </Tag>
                  <Tag>{d.volumeEnabled ? `${d.volumeStrategy === 'random' ? '随机' : '固定'}分卷` : '不分卷'}</Tag>
                  <Tag color={d.cacheEnabled ? 'blue' : 'default'}>缓存{d.cacheEnabled ? '开' : '关'}</Tag>
                </>
              ),
            },
            {
              title: '创建时间',
              dataIndex: 'createdAt',
              width: 170,
              render: (v: number) => formatTime(v),
            },
            {
              title: '操作',
              key: 'ops',
              width: 160,
              render: (_, d) => (
                <Space size={0}>
                  <Button type="text" size="small" onClick={() => onTest(d)}>测试</Button>
                  <Button type="text" size="small" onClick={() => openEdit(d)}>编辑</Button>
                  <Dropdown menu={moreMenu(d)} trigger={['click']}>
                    <Button type="text" size="small" icon={<MoreOutlined />} />
                  </Dropdown>
                </Space>
              ),
            },
          ]}
        />
      </Card></>
    );
  }

  return (
    <>{heading}{modalNode}{filterBar}{batchBar}
    {filtered.length === 0 ? noMatch : (
    <Row gutter={[18, 18]}>
      {filtered.map((d) => {
        return (
          <Col key={d.id} xs={24} sm={12} lg={8} xl={6}>
            <Card className="source-card"
              hoverable
              onClick={() => navigate(`/browse/${d.id}`)}
              actions={[
                <Button key="test" type="text" size="small" onClick={(e) => { e.stopPropagation(); onTest(d); }}>测试</Button>,
                <Button key="edit" type="text" size="small" onClick={(e) => { e.stopPropagation(); openEdit(d); }}>编辑</Button>,
                <Dropdown key="more" menu={moreMenu(d)} trigger={['click']}>
                  <Button type="text" size="small" icon={<MoreOutlined />} onClick={(e) => e.stopPropagation()} />
                </Dropdown>,
              ]}
            >
              <Checkbox
                className="source-card-check"
                checked={selectedIds.includes(d.id)}
                onClick={(e) => e.stopPropagation()}
                onChange={(e) => toggleSelected(d.id, e.target.checked)}
              />
              <Card.Meta
                avatar={<span className="source-icon"><DatabaseOutlined /></span>}
                title={d.name}
                description={
                  <>
                    <div>
                      {typeTag(d)}
                      <Tag color={d.encryptionEnabled ? 'green' : 'default'}>
                        {d.encryptionEnabled ? '已加密' : '未加密'}
                      </Tag>
                      <Tag>{d.volumeEnabled ? `${d.volumeStrategy === 'random' ? '随机' : '固定'}分卷` : '不分卷'}</Tag>
                      <Tag color={d.cacheEnabled ? 'blue' : 'default'}>缓存{d.cacheEnabled ? '开' : '关'}</Tag>
                    </div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      创建于 {formatTime(d.createdAt)} · 点击进入文件浏览器
                    </Typography.Text>
                  </>
                }
              />
            </Card>
          </Col>
        );
      })}
    </Row>
    )}</>
  );
}

function PageHeading({
  onAdd,
  onImport,
  view,
  onViewChange,
}: {
  onAdd: () => void;
  onImport: () => void;
  view: 'card' | 'list';
  onViewChange: (v: 'card' | 'list') => void;
}) {
  return <div className="page-heading"><div><span className="page-kicker">STORAGE MATRIX</span>
    <h1>数据空间</h1><p>从一个统一入口访问并管理本地、WebDAV 与网盘中的受保护数据。连接、加密、分卷与缓存配置均归属于数据源。</p></div>
    <Space>
      <Segmented
        value={view}
        onChange={(v) => onViewChange(v as 'card' | 'list')}
        options={[
          { value: 'card', icon: <AppstoreOutlined />, title: '卡片视图' },
          { value: 'list', icon: <BarsOutlined />, title: '列表视图' },
        ]}
      />
      <Button icon={<ImportOutlined />} onClick={onImport}>导入</Button>
      <Button type="primary" icon={<PlusOutlined />} onClick={onAdd}>添加数据源</Button>
    </Space></div>;
}
