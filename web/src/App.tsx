import {
  DatabaseOutlined, FolderOpenOutlined, LogoutOutlined, SettingOutlined,
  SwapOutlined, SafetyCertificateOutlined,
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
import { useAuth } from './stores/auth';
import { useTasks } from './stores/tasks';
import { startTransferPolling, useTransfers } from './stores/transfers';
import { formatBytes } from './utils/format';

export default function App() {
  const auth = useAuth();
  const [initError, setInitError] = useState<string | null>(null);

  useEffect(() => {
    auth.init().catch((error: unknown) =>
      setInitError(error instanceof Error ? error.message : String(error)));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (initError) return <Centered><Typography.Text type="danger">无法连接服务端：{initError}</Typography.Text></Centered>;
  if (auth.required === null) return <Centered><Spin size="large" /></Centered>;
  if (auth.required && !auth.authed) return <LoginPage />;
  return <MainLayout />;
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="app-centered"><div className="center-glow" />{children}</div>;
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const width = 66; const height = 20;
  const max = Math.max(1, ...values);
  const points = (values.length ? values : [0]).map((value, index, list) => {
    const x = list.length === 1 ? width : index * width / (list.length - 1);
    const y = height - 2 - (value / max) * (height - 4);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return <svg className="speed-spark" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
    <polyline points={points} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" />
  </svg>;
}

function SpeedPill({ direction, value, history }: {
  direction: 'up' | 'down'; value: number; history: number[];
}) {
  const upload = direction === 'up';
  return <div className={`speed-pill ${upload ? 'upload' : 'download'}`} title={upload ? '服务端向网盘上传' : '服务端从网盘下载'}>
    <span className="speed-direction">{upload ? '↑' : '↓'}</span>
    <Sparkline values={history} color={upload ? '#9b7bff' : '#38bdf8'} />
    <span className="speed-value">{formatBytes(value)}<small>/s</small></span>
  </div>;
}

function MainLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const auth = useAuth();
  const tasks = useTasks((state) => state.tasks);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => startTransferPolling(), []);

  const activeCount = tasks.filter((task) => task.status === 'running' || task.status === 'queued').length;
  const selected = location.pathname.startsWith('/browse') ? '/' : `/${location.pathname.split('/')[1] ?? ''}`;

  return <Layout className="app-shell">
    <Layout.Header className="app-header">
      <button className="brand" onClick={() => navigate('/')} aria-label="返回数据管理">
        <span className="brand-logo"><SafetyCertificateOutlined /></span>
        <span className="brand-copy"><b>SAFEDRIVE</b><small>ZERO TRUST STORAGE</small></span>
      </button>
      <Menu className="top-nav" mode="horizontal" selectedKeys={[selected]} onClick={(event) => navigate(event.key)} items={[
        { key: '/', icon: <FolderOpenOutlined />, label: '数据管理' },
        { key: '/sources', icon: <DatabaseOutlined />, label: '数据源' },
        { key: '/settings', icon: <SettingOutlined />, label: '设置' },
      ]} />
      <div className="header-actions">
        <HeaderSpeeds />
        <Badge count={activeCount} size="small" offset={[-2, 2]}>
          <Button className="queue-button" icon={<SwapOutlined />} onClick={() => setDrawerOpen(true)}>
            传输队列
          </Button>
        </Badge>
        {auth.required && <Button type="text" icon={<LogoutOutlined />} onClick={() => auth.logout()} aria-label="退出登录" />}
      </div>
    </Layout.Header>
    <Layout.Content className="app-content">
      <main className="page-frame" key={selected}>
        <Routes>
          <Route path="/" element={<DataPage />} />
          <Route path="/browse/:dsId" element={<BrowserPage />} />
          <Route path="/sources" element={<SourcesPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </Layout.Content>
    <TaskDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
  </Layout>;
}

function HeaderSpeeds() {
  const upload = useTransfers((state) => state.snapshot.uploadSpeed);
  const download = useTransfers((state) => state.snapshot.downloadSpeed);
  const uploadHistory = useTransfers((state) => state.uploadHistory);
  const downloadHistory = useTransfers((state) => state.downloadHistory);
  return <div className="speed-cluster">
    <SpeedPill direction="up" value={upload} history={uploadHistory} />
    <SpeedPill direction="down" value={download} history={downloadHistory} />
  </div>;
}
