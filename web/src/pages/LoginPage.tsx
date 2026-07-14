import { Alert, Button, Card, Form, Input, Typography } from 'antd';
import { useState } from 'react';
import { useAuth } from '../stores/auth';

/** 服务端管理密码登录（仅在服务端配置了 --admin-password 时出现）。 */
export default function LoginPage() {
  const auth = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onFinish = async ({ password }: { password: string }) => {
    setLoading(true);
    setError(null);
    try {
      await auth.login(password);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f0f2f5' }}>
      <Card style={{ width: 380 }}>
        <Typography.Title level={4}>🔐 SafeDrive · 服务端登录</Typography.Title>
        <Typography.Paragraph type="secondary">
          此密码仅用于访问服务端 API，与密码本主密码无关。
        </Typography.Paragraph>
        {error && <Alert type="error" message={error} style={{ marginBottom: 16 }} />}
        <Form onFinish={onFinish}>
          <Form.Item name="password" rules={[{ required: true, message: '请输入管理密码' }]}>
            <Input.Password placeholder="管理密码" autoFocus />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  );
}
