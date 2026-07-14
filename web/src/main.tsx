import { App as AntApp, ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';

// 旧版本注册过 Service Worker（浏览器端解密隧道），现已由服务端 /stream
// 取代 —— 主动注销，避免残留 SW 拦截请求。
if ('serviceWorker' in navigator) {
  void navigator.serviceWorker.getRegistrations().then((regs) => {
    for (const r of regs) void r.unregister();
  });
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#2f54eb' } }}>
      <AntApp>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
