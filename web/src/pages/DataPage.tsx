import { DatabaseOutlined, FolderOpenOutlined } from '@ant-design/icons';
import { App, Button, Card, Col, Empty, Row, Skeleton, Tag, Typography } from 'antd';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSources } from '../stores/sources';

/** 数据管理首页：数据源入口卡片。 */
export default function DataPage() {
  const { message } = App.useApp();
  const sources = useSources();
  const navigate = useNavigate();

  useEffect(() => {
    void sources.refresh().catch((e: unknown) => message.error(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!sources.loaded) return <><PageHeading /><Row gutter={[16,16]}>{[0,1,2].map((key) => <Col key={key} xs={24} sm={12} lg={8}><Card><Skeleton active avatar paragraph={{rows:2}} /></Card></Col>)}</Row></>;
  if (sources.list.length === 0) {
    return (
      <><PageHeading /><Card><Empty description="还没有数据源">
        <Button type="primary" onClick={() => navigate('/sources')}>
          去添加数据源
        </Button>
      </Empty></Card></>
    );
  }

  return (
    <><PageHeading /><Row gutter={[18, 18]}>
      {sources.list.map((d) => {
        return (
          <Col key={d.id} xs={24} sm={12} lg={8} xl={6}>
            <Card className="source-card"
              hoverable
              onClick={() => navigate(`/browse/${d.id}`)}
            >
              <Card.Meta
                avatar={<span className="source-icon"><DatabaseOutlined /></span>}
                title={d.name}
                description={
                  <>
                    <div>
                      {d.type === 'localfs' ? (
                        <Tag color="geekblue">本地文件系统</Tag>
                      ) : d.type === 'baidupan' ? (
                        <Tag color="blue">百度网盘</Tag>
                      ) : (
                        <Tag color="cyan">WebDAV</Tag>
                      )}
                      <Tag color={d.encryptionEnabled ? 'green' : 'default'}>
                        {d.encryptionEnabled ? '已加密' : '未加密'}
                      </Tag>
                      <Tag>{d.volumeEnabled ? '已分卷' : '不分卷'}</Tag>
                    </div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      <FolderOpenOutlined /> 点击进入文件浏览器
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

function PageHeading() {
  return <div className="page-heading"><div><span className="page-kicker">STORAGE MATRIX</span>
    <h1>数据空间</h1><p>从一个统一入口访问本地、WebDAV 与网盘中的受保护数据。</p></div></div>;
}
