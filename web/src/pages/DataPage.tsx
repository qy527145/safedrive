import { DatabaseOutlined, FolderOpenOutlined } from '@ant-design/icons';
import { App, Button, Card, Col, Empty, Row, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type Strategy } from '../api/client';
import { useSources } from '../stores/sources';

/** 数据管理首页：数据源入口卡片。 */
export default function DataPage() {
  const { message } = App.useApp();
  const sources = useSources();
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    void sources.refresh().catch((e: unknown) => message.error(String(e)));
    void api.listStrategies().then(setStrategies).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (sources.loaded && sources.list.length === 0) {
    return (
      <Empty description="还没有数据源">
        <Button type="primary" onClick={() => navigate('/sources')}>
          去添加数据源
        </Button>
      </Empty>
    );
  }

  return (
    <Row gutter={[16, 16]}>
      {sources.list.map((d) => {
        const strategy = strategies.find((s) => s.id === d.strategyId);
        return (
          <Col key={d.id} xs={24} sm={12} lg={8} xl={6}>
            <Card
              hoverable
              onClick={() => {
                if (!strategy) {
                  message.error('该数据源绑定的策略已不存在，请先在「数据源管理」重新绑定');
                  return;
                }
                navigate(`/browse/${d.id}`);
              }}
            >
              <Card.Meta
                avatar={<DatabaseOutlined style={{ fontSize: 28, color: '#2f54eb' }} />}
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
                      {strategy ? (
                        <Tag color="purple">{strategy.name}</Tag>
                      ) : (
                        <Tag color="error">策略缺失</Tag>
                      )}
                    </div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      <FolderOpenOutlined /> 点击进入加密文件浏览器
                    </Typography.Text>
                  </>
                }
              />
            </Card>
          </Col>
        );
      })}
    </Row>
  );
}
