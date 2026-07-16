import { AppstoreOutlined, BarsOutlined, DatabaseOutlined, PlusOutlined } from '@ant-design/icons';
import { App, Button, Card, Col, Empty, Row, Segmented, Skeleton, Space, Table, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type DsRecord } from '../api/client';
import SourceModal from '../components/SourceModal';
import { useSources } from '../stores/sources';
import { formatTime } from '../utils/format';

/** 数据管理首页：数据源入口（卡片/列表两种呈现）+ 添加/编辑/删除管理。 */
export default function DataPage() {
  const { message, modal } = App.useApp();
  const sources = useSources();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DsRecord | null>(null);
  // 呈现方式：卡片 / 列表，记忆在本地
  const [view, setView] = useState<'card' | 'list'>(() =>
    localStorage.getItem('sd.view.sources') === 'list' ? 'list' : 'card',
  );
  const changeView = (v: 'card' | 'list') => {
    setView(v);
    localStorage.setItem('sd.view.sources', v);
  };

  useEffect(() => {
    void sources.refresh().catch((e: unknown) => message.error(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openCreate = () => { setEditing(null); setOpen(true); };
  const openEdit = (d: DsRecord) => { setEditing(d); setOpen(true); };
  const onTest = (d: DsRecord) => void api.testDs(d.id)
    .then((r) => message.success(`连接正常（${r.entries} 个条目）`))
    .catch((e: unknown) => message.error(String(e)));
  const onDelete = (d: DsRecord) => modal.confirm({
    title: `删除数据源「${d.name}」？`,
    content: '只删除连接配置，不删除远端数据。',
    onOk: async () => { await api.deleteDs(d.id); await sources.refresh(); },
  });

  const modalNode = <SourceModal open={open} editing={editing} onClose={() => setOpen(false)} />;
  const heading = <PageHeading onAdd={openCreate} view={view} onViewChange={changeView} />;

  if (!sources.loaded) return <>{heading}{modalNode}<Row gutter={[16,16]}>{[0,1,2].map((key) => <Col key={key} xs={24} sm={12} lg={8}><Card><Skeleton active avatar paragraph={{rows:2}} /></Card></Col>)}</Row></>;
  if (sources.list.length === 0) {
    return (
      <>{heading}{modalNode}<Card><Empty description="还没有数据源">
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
          添加数据源
        </Button>
      </Empty></Card></>
    );
  }

  const typeTag = (d: DsRecord) =>
    d.type === 'localfs' ? (
      <Tag color="geekblue">本地文件系统</Tag>
    ) : d.type === 'baidupan' ? (
      <Tag color="blue">百度网盘</Tag>
    ) : (
      <Tag color="cyan">WebDAV</Tag>
    );

  if (view === 'list') {
    return (
      <>{heading}{modalNode}<Card styles={{ body: { paddingTop: 16 } }}>
        <Table<DsRecord>
          rowKey="id"
          dataSource={sources.list}
          pagination={false}
          size="middle"
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
              width: 180,
              render: (_, d) => (
                <Space size={0}>
                  <Button type="text" size="small" onClick={() => onTest(d)}>测试</Button>
                  <Button type="text" size="small" onClick={() => openEdit(d)}>编辑</Button>
                  <Button type="text" size="small" danger onClick={() => onDelete(d)}>删除</Button>
                </Space>
              ),
            },
          ]}
        />
      </Card></>
    );
  }

  return (
    <>{heading}{modalNode}<Row gutter={[18, 18]}>
      {sources.list.map((d) => {
        return (
          <Col key={d.id} xs={24} sm={12} lg={8} xl={6}>
            <Card className="source-card"
              hoverable
              onClick={() => navigate(`/browse/${d.id}`)}
              actions={[
                <Button key="test" type="text" size="small" onClick={(e) => { e.stopPropagation(); onTest(d); }}>测试</Button>,
                <Button key="edit" type="text" size="small" onClick={(e) => { e.stopPropagation(); openEdit(d); }}>编辑</Button>,
                <Button key="delete" type="text" size="small" danger onClick={(e) => { e.stopPropagation(); onDelete(d); }}>删除</Button>,
              ]}
            >
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
    </Row></>
  );
}

function PageHeading({
  onAdd,
  view,
  onViewChange,
}: {
  onAdd: () => void;
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
      <Button type="primary" icon={<PlusOutlined />} onClick={onAdd}>添加数据源</Button>
    </Space></div>;
}
