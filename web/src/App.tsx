import {
  DatabaseOutlined,
  FolderOpenOutlined,
  LogoutOutlined,
  SettingOutlined,
  SwapOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Badge, Button, Layout, Menu, Spin, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import TaskDrawer from './components/TaskDrawer';
import BrowserPage from './pages/BrowserPage';
import DataPage from './pages/DataPage';
import LoginPage from './pages/LoginPage';
import SettingsPage from './pages/SettingsPage';
import SourcesPage from './pages/SourcesPage';
import StrategiesPage from './pages/StrategiesPage';
import { useAuth } from './stores/auth';
import { useTasks } from './stores/tasks';

export default function App() {
  const auth = useAuth();
  const [initError, setInitError] = useState<string | null>(null);

  useEffect(() => {
    auth.init().catch((e: unknown) => setInitError(e instanceof Error ? e.message : String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (initError) {
    return (
      <Centered>
        <Typography.Text type="danger">无法连接服务端：{initError}</Typography.Text>
      </Centered>
    );
  }
  if (auth.required === null) {
    return (
      <Centered>
        <Spin size="large" />
      </Centered>
    );
  }
  if (auth.required && !auth.authed) return <LoginPage />;
  return <MainLayout />;
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {children}
    </div>
  );
}

function MainLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const auth = useAuth();
  const tasks = useTasks((s) => s.tasks);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const activeCount = tasks.filter((t) => t.status === 'running' || t.status === 'queued').length;
  const selected = location.pathname.startsWith('/browse')
    ? '/'
    : `/${location.pathname.split('/')[1] ?? ''}`;

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Sider theme="dark" width={208}>
        <div style={{ color: '#fff', padding: '18px 20px', fontSize: 17, fontWeight: 600 }}>
          🔐 SafeDrive
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selected]}
          onClick={(e) => navigate(e.key)}
          items={[
            { key: '/', icon: <FolderOpenOutlined />, label: '数据管理' },
            { key: '/strategies', icon: <ThunderboltOutlined />, label: '策略管理' },
            { key: '/sources', icon: <DatabaseOutlined />, label: '数据源管理' },
            { key: '/settings', icon: <SettingOutlined />, label: '设置' },
          ]}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Header
          style={{
            background: '#fff',
            padding: '0 24px',
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            gap: 12,
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Badge count={activeCount} size="small">
            <Button icon={<SwapOutlined />} onClick={() => setDrawerOpen(true)}>
              传输队列
            </Button>
          </Badge>
          {auth.required && (
            <Button icon={<LogoutOutlined />} onClick={() => auth.logout()}>
              退出登录
            </Button>
          )}
        </Layout.Header>
        <Layout.Content style={{ padding: 24 }}>
          <Routes>
            <Route path="/" element={<DataPage />} />
            <Route path="/browse/:dsId" element={<BrowserPage />} />
            <Route path="/strategies" element={<StrategiesPage />} />
            <Route path="/sources" element={<SourcesPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout.Content>
      </Layout>
      <TaskDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </Layout>
  );
}
