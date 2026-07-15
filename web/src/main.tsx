import { App as AntApp, ConfigProvider, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import './app.css';

// 旧版本注册过 Service Worker（浏览器端解密隧道），现已由服务端 /stream
// 取代 —— 主动注销，避免残留 SW 拦截请求。
if ('serviceWorker' in navigator) {
  void navigator.serviceWorker.getRegistrations().then((regs) => {
    for (const r of regs) void r.unregister();
  });
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{
      algorithm: theme.darkAlgorithm,
      token: {
        colorPrimary: '#6ea8ff', colorInfo: '#38bdf8', colorSuccess: '#4ade80',
        colorWarning: '#fbbf24', colorError: '#f87171', colorBgBase: '#0a0c12',
        colorBgContainer: '#141823', colorBgElevated: '#1b202c', colorBorder: '#262c3a',
        colorText: '#e8ecf3', colorTextSecondary: '#aab3c5', borderRadius: 10,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
      },
      components: {
        Layout: { headerBg: 'transparent', bodyBg: 'transparent' },
        Menu: { darkItemBg: 'transparent', darkSubMenuItemBg: 'transparent', itemBg: 'transparent' },
        Table: { headerBg: '#10141e', rowHoverBg: '#1b202c' },
      },
    }}>
      <AntApp>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
