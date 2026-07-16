import { App, Card, Checkbox, Form, Input, Modal, Select, Switch, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { api, type DsRecord } from '../api/client';
import { useSources } from '../stores/sources';
import { parseSize, sizeToInput } from '../utils/format';

interface FormValues {
  name: string; type: 'localfs' | 'webdav' | 'baidupan'; root?: string; url?: string;
  username?: string; password?: string; bduss?: string; userAgent?: string;
  clientId?: string; clientSecret?: string; encryptionEnabled: boolean;
  encryptionPassword?: string; volumeEnabled: boolean; volumeText: string;
  volumeStrategy: 'fixed' | 'random'; volumeNameFormat: string; cacheEnabled: boolean;
}

/** 添加/编辑数据源弹窗：连接、加密、分卷与缓存配置均归属于数据源。 */
export default function SourceModal({ open, editing, onClose }: {
  open: boolean; editing: DsRecord | null; onClose: () => void;
}) {
  const { message } = App.useApp();
  const sources = useSources();
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm<FormValues>();
  const type = Form.useWatch('type', form) ?? 'localfs';
  const encrypted = Form.useWatch('encryptionEnabled', form) ?? true;
  const volume = Form.useWatch('volumeEnabled', form) ?? true;

  useEffect(() => {
    if (!open) return;
    form.resetFields();
    if (editing) {
      const d = editing;
      form.setFieldsValue({ name:d.name, type:d.type, root:d.config.root, url:d.config.url,
        username:d.config.username, password:d.config.password, bduss:d.config.bduss,
        userAgent:d.config.userAgent, clientId:d.config.clientId, clientSecret:d.config.clientSecret,
        encryptionEnabled:d.encryptionEnabled, encryptionPassword:d.password,
        volumeEnabled:d.volumeEnabled, volumeText:sizeToInput(d.volumeSize),
        volumeStrategy:d.volumeStrategy, volumeNameFormat:d.volumeNameFormat, cacheEnabled:d.cacheEnabled });
    } else {
      form.setFieldsValue({ type: 'localfs', encryptionEnabled: true, volumeEnabled: true,
        volumeText: '300M', volumeStrategy: 'random', volumeNameFormat: '{s}_{i}.bin', cacheEnabled: true });
    }
  }, [open, editing, form]);

  const onSubmit = async () => {
    const v = await form.validateFields();
    const oldBduss = editing?.config.bduss;
    const preserve = oldBduss === v.bduss && (editing?.config.clientId ?? '') === (v.clientId ?? '') &&
      (editing?.config.clientSecret ?? '') === (v.clientSecret ?? '');
    const config: Record<string,string | number> = v.type === 'localfs' ? {root:v.root ?? ''} :
      v.type === 'webdav' ? {url:v.url ?? '',username:v.username ?? '',password:v.password ?? ''} :
      {root:v.root ?? '/safedrive',bduss:v.bduss ?? '',userAgent:v.userAgent ?? '',
       clientId:v.clientId ?? '',clientSecret:v.clientSecret ?? '',
       accessToken:preserve ? editing?.config.accessToken ?? '' : '',
       refreshToken:preserve ? editing?.config.refreshToken ?? '' : '',
       ...(preserve && editing?.config.accessTokenExpiresAt
         ? {accessTokenExpiresAt:editing.config.accessTokenExpiresAt} : {}),
      };
    const body = {name:v.name,type:v.type,config,encryptionEnabled:v.encryptionEnabled,
      password:v.encryptionPassword || undefined,volumeEnabled:v.volumeEnabled,
      volumeSize:v.volumeEnabled ? parseSize(v.volumeText) ?? 0 : 0,volumeStrategy:v.volumeStrategy,
      volumeNameFormat:v.volumeNameFormat,cacheEnabled:v.cacheEnabled};
    setSaving(true);
    try {
      const saved = editing ? await api.updateDs(editing.id, body) : await api.createDs(body);
      await sources.refresh(); onClose();
      try { const r=await api.testDs(saved.id); message.success(`已保存，连接正常（根目录 ${r.entries} 个条目）`); }
      catch(e) { message.warning(`已保存，但连接测试失败：${e instanceof Error?e.message:e}`); }
    } catch(e) { message.error(e instanceof Error?e.message:String(e)); } finally { setSaving(false); }
  };

  return <Modal title={editing?'编辑数据源':'添加数据源'} open={open} confirmLoading={saving} onOk={()=>void onSubmit()} onCancel={onClose} destroyOnHidden width={620}>
    <Form form={form} layout="vertical" name="ds">
      <Form.Item name="name" label="数据源名称" rules={[{required:true}]}><Input/></Form.Item>
      <Form.Item name="type" label="类型" rules={[{required:true}]}><Select disabled={!!editing} options={[{label:'本地文件系统',value:'localfs'},{label:'WebDAV',value:'webdav'},{label:'百度网盘',value:'baidupan'}]}/></Form.Item>
      {type==='localfs'&&<Form.Item name="root" label="根目录" rules={[{required:true}]}><Input/></Form.Item>}
      {type==='webdav'&&<><Form.Item name="url" label="WebDAV 地址" rules={[{required:true},{pattern:/^https?:\/\//}]}><Input/></Form.Item><Form.Item name="username" label="用户名"><Input/></Form.Item><Form.Item name="password" label="密码"><Input.Password/></Form.Item></>}
      {type==='baidupan'&&<><Form.Item name="root" label="网盘根目录" rules={[{required:true}]}><Input/></Form.Item><Form.Item name="clientId" label="开放平台 API Key（可选）"><Input/></Form.Item><Form.Item name="clientSecret" label="Secret Key（可选）"><Input.Password/></Form.Item><Form.Item name="bduss" label="BDUSS" rules={[{required:true}]}><Input.Password/></Form.Item><Form.Item name="userAgent" label="下载 User-Agent"><Input/></Form.Item></>}
      <Card size="small" title="数据保护" style={{marginBottom:16}}>
        <Form.Item name="encryptionEnabled" label="内容加密" valuePropName="checked" extra={editing?'创建后不可修改；如需切换请新建数据源。':'该选择创建后不可更改。'}><Switch disabled={!!editing}/></Form.Item>
        {encrypted&&<Form.Item name="encryptionPassword" label="根密码" rules={[{required:!editing,message:'请输入密码'}]} extra={editing?'修改后会重命名存储端根层加密文件名；留空保持原密码。':'丢失后无法恢复数据。'}><Input.Password/></Form.Item>}
        <Form.Item name="volumeEnabled" valuePropName="checked" extra={editing?'创建后不可修改。':''}><Checkbox disabled={!!editing}>启用分卷</Checkbox></Form.Item>
        {volume&&<><Form.Item name="volumeText" label="最大分卷大小" rules={[{required:true},{validator:(_,v)=>{const n=parseSize(v??'');return n!=null&&n>=64*1024?Promise.resolve():Promise.reject(new Error('至少 64K，例如 300M'));}}]}><Input/></Form.Item>
        <Form.Item name="volumeStrategy" label="分卷策略"><Select options={[{label:'随机大小（默认，卷数与固定策略一致）',value:'random'},{label:'固定大小',value:'fixed'}]}/></Form.Item>
        {!encrypted&&<Form.Item name="volumeNameFormat" label="分卷名称格式" rules={[{required:true},{validator:(_,v:string)=>v?.includes('{i}')?Promise.resolve():Promise.reject(new Error('必须包含 {i}'))}]} extra="{s} 为原文件名，{i} 为位数对齐的分卷序号"><Input placeholder="{s}_{i}.bin"/></Form.Item>}</>}
        {encrypted&&volume&&<Typography.Text type="secondary">加密场景沿用由文件密钥派生的随机分卷名称，不开放自定义模板。</Typography.Text>}
        <Form.Item name="cacheEnabled" valuePropName="checked" style={{marginTop:12}}><Checkbox>允许该数据源使用持久下载缓存</Checkbox></Form.Item>
      </Card>
    </Form>
  </Modal>;
}
