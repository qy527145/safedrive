import { QrcodeOutlined, ReloadOutlined } from '@ant-design/icons';
import { App, Button, Card, Checkbox, Form, Input, Modal, Select, Spin, Switch, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { api, type DsRecord, type DsType } from '../api/client';
import { useSources } from '../stores/sources';
import { parseSize, sizeToInput } from '../utils/format';

interface FormValues {
  name: string; type: DsType; root?: string; url?: string;
  username?: string; password?: string; bduss?: string; userAgent?: string;
  clientId?: string; clientSecret?: string; refreshToken?: string;
  driveType?: string; apiBase?: string; cookie?: string; encryptionEnabled: boolean;
  encryptionPassword?: string; volumeEnabled: boolean; volumeText: string;
  volumeStrategy: 'fixed' | 'random'; volumeNameFormat: string; cacheEnabled: boolean;
}

const DS_TYPES: { label: string; value: DsType }[] = [
  { label: '本地文件系统', value: 'localfs' },
  { label: 'WebDAV', value: 'webdav' },
  { label: '百度网盘', value: 'baidupan' },
  { label: '阿里云盘', value: 'aliyundrive' },
  { label: '夸克网盘', value: 'quark' },
];

const trim = (s?: string) => (s ?? '').trim();

/**
 * 表单值 → 数据源 config。只提交「用户填的」字段：accessToken / driveId 这类
 * 运行期产物，以及后台轮换过的 refreshToken / cookie，都由服务端在保存时按
 * 「账号有没有换」自行保留，前端回写反而会把刚轮换出来的凭证顶掉。
 */
function buildConfig(v: FormValues, editing: DsRecord | null): Record<string, string | number> {
  switch (v.type) {
    case 'localfs':
      return { root: v.root ?? '' };
    case 'webdav':
      return { url: trim(v.url), username: v.username ?? '', password: v.password ?? '' };
    case 'aliyundrive':
      return { root: trim(v.root), clientId: trim(v.clientId), clientSecret: trim(v.clientSecret),
        refreshToken: trim(v.refreshToken), driveType: v.driveType || 'default', apiBase: trim(v.apiBase) };
    case 'quark':
      return { root: trim(v.root), cookie: trim(v.cookie), apiBase: trim(v.apiBase) };
    default:
      // 编辑时若把 BDUSS 留空，视为沿用原值（表单里本来就是回填的）。
      return { root: v.root ?? '/safedrive', bduss: trim(v.bduss) || trim(editing?.config.bduss),
        userAgent: v.userAgent ?? '', clientId: trim(v.clientId), clientSecret: trim(v.clientSecret) };
  }
}

/** 添加/编辑/克隆数据源弹窗：连接、加密、分卷与缓存配置均归属于数据源。
 * `cloneFrom` 提供时按「以它为模板新建」处理：预填全部配置，保存走创建接口。 */export default function SourceModal({ open, editing, cloneFrom = null, onClose }: {
  open: boolean; editing: DsRecord | null; cloneFrom?: DsRecord | null; onClose: () => void;
}) {
  const { message, modal } = App.useApp();
  const sources = useSources();
  const [saving, setSaving] = useState(false);
  const [qrOpen, setQrOpen] = useState(false);
  const [aliQrOpen, setAliQrOpen] = useState(false);
  const [form] = Form.useForm<FormValues>();
  const type = Form.useWatch('type', form) ?? 'localfs';
  const encrypted = Form.useWatch('encryptionEnabled', form) ?? true;
  const volume = Form.useWatch('volumeEnabled', form) ?? true;
  const clientId = Form.useWatch('clientId', form) ?? '';
  const clientSecret = Form.useWatch('clientSecret', form) ?? '';
  const apiBase = Form.useWatch('apiBase', form) ?? '';

  useEffect(() => {
    if (!open) return;
    form.resetFields();
    const template = editing ?? cloneFrom;
    if (template) {
      const d = template;
      form.setFieldsValue({ name:editing?d.name:`${d.name} 副本`, type:d.type, root:d.config.root, url:d.config.url,
        username:d.config.username, password:d.config.password, bduss:d.config.bduss,
        userAgent:d.config.userAgent, clientId:d.config.clientId, clientSecret:d.config.clientSecret,
        refreshToken:d.config.refreshToken, driveType:d.config.driveType ?? 'default',
        apiBase:d.config.apiBase, cookie:d.config.cookie,
        encryptionEnabled:d.encryptionEnabled, encryptionPassword:d.password,
        volumeEnabled:d.volumeEnabled, volumeText:sizeToInput(d.volumeSize),
        volumeStrategy:d.volumeStrategy, volumeNameFormat:d.volumeNameFormat, cacheEnabled:d.cacheEnabled });
    } else {
      form.setFieldsValue({ type: 'localfs', encryptionEnabled: true, volumeEnabled: true, driveType: 'default',
        volumeText: '300M', volumeStrategy: 'random', volumeNameFormat: '{s}_{i}.bin', cacheEnabled: true });
    }
  }, [open, editing, cloneFrom, form]);

  /** 表单动过就先确认再关，避免误触（遮罩点击 / Esc / 取消 / X 都会走这里）。 */
  const confirmClose = () => {
    if (!form.isFieldsTouched()) { onClose(); return; }
    modal.confirm({
      title: '放弃未保存的修改？',
      content: '关闭后已填写的内容将丢失。',
      okText: '放弃修改',
      okButtonProps: { danger: true },
      cancelText: '继续编辑',
      onOk: onClose,
    });
  };

  const onSubmit = async () => {
    const v = await form.validateFields();
    const config = buildConfig(v, editing);
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

  const onQrSuccess = useCallback((bduss: string) => {
    // touched: 让 confirmClose 把扫码结果也视为「未保存的修改」
    form.setFields([{ name: 'bduss', value: bduss, touched: true, errors: [] }]);
    setQrOpen(false);
    void message.success('登录成功，BDUSS 已自动填入');
  }, [form, message]);

  /** 扫码前先确认应用凭据填了 —— 没有它们连二维码都换不到。 */
  const openAliyunQr = async () => {
    try { await form.validateFields(['clientId', 'clientSecret']); } catch { return; }
    setAliQrOpen(true);
  };

  const onAliyunQrSuccess = useCallback((refreshToken: string) => {
    form.setFields([{ name: 'refreshToken', value: refreshToken, touched: true, errors: [] }]);
    setAliQrOpen(false);
    void message.success('授权成功，refresh_token 已自动填入');
  }, [form, message]);

  return <Modal title={editing?'编辑数据源':cloneFrom?'克隆数据源':'添加数据源'} open={open} confirmLoading={saving} onOk={()=>void onSubmit()} onCancel={confirmClose} destroyOnHidden width={620}>
    <Form form={form} layout="vertical" name="ds">
      <Form.Item name="name" label="数据源名称" rules={[{required:true}]}><Input/></Form.Item>
      <Form.Item name="type" label="类型" rules={[{required:true}]}><Select disabled={!!editing} options={DS_TYPES}/></Form.Item>
      {type==='localfs'&&<Form.Item name="root" label="根目录" rules={[{required:true}]}><Input/></Form.Item>}
      {type==='webdav'&&<><Form.Item name="url" label="WebDAV 地址" rules={[{required:true},{pattern:/^https?:\/\//}]}><Input/></Form.Item><Form.Item name="username" label="用户名"><Input/></Form.Item><Form.Item name="password" label="密码"><Input.Password/></Form.Item></>}
      {type==='baidupan'&&<><Form.Item name="root" label="网盘根目录" rules={[{required:true}]}><Input/></Form.Item><Form.Item name="clientId" label="开放平台 API Key（可选）"><Input/></Form.Item><Form.Item name="clientSecret" label="Secret Key（可选）"><Input.Password/></Form.Item>
      <Form.Item name="bduss" label="BDUSS" rules={[{required:true,message:'请扫码登录获取，或手动粘贴'}]} extra={<Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>setQrOpen(true)}>扫码登录自动获取</Button>}><Input.Password placeholder="点击下方扫码登录自动获取，或手动粘贴 Cookie 中的 BDUSS"/></Form.Item>
      <Form.Item name="userAgent" label="下载 User-Agent" extra="留空使用默认值，仅影响下载数据流量的 UA 标识"><Input placeholder="netdisk;P2SP;2.2.61.31;android"/></Form.Item></>}
      {type==='aliyundrive'&&<><Form.Item name="root" label="网盘根目录" extra="留空即网盘根目录；建议单独用一个目录"><Input placeholder="/safedrive"/></Form.Item>
      <Form.Item name="driveType" label="盘位" extra="资源库容量大且不占备份盘配额，备份盘对应手机备份目录"><Select options={[{label:'默认盘',value:'default'},{label:'资源库',value:'resource'},{label:'备份盘',value:'backup'}]}/></Form.Item>
      <Form.Item name="clientId" label="client_id" rules={[{required:true}]} extra="阿里云盘开放平台自建应用的凭据；只在本机与阿里官方接口之间流转，不经第三方中转"><Input/></Form.Item>
      <Form.Item name="clientSecret" label="client_secret" rules={[{required:true}]}><Input.Password/></Form.Item>
      <Form.Item name="refreshToken" label="refresh_token" rules={[{required:true,message:'请扫码授权获取，或手动粘贴'}]} extra={<Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>void openAliyunQr()}>扫码授权自动获取</Button>}><Input.Password placeholder="点击下方扫码授权自动获取，令牌过期会自动轮换"/></Form.Item>
      <Form.Item name="apiBase" label="接口地址" extra="留空使用 https://openapi.alipan.com"><Input placeholder="https://openapi.alipan.com"/></Form.Item></>}
      {type==='quark'&&<><Form.Item name="root" label="网盘根目录" extra="留空即网盘根目录；建议单独用一个目录"><Input placeholder="/safedrive"/></Form.Item>
      <Form.Item name="cookie" label="Cookie" rules={[{required:true}]} extra="浏览器登录 pan.quark.cn 后复制整串 Cookie（需包含 __puus）；后台会自动续期并回写"><Input.TextArea rows={3} autoComplete="off" placeholder="__pus=...; __puus=...; ..."/></Form.Item>
      <Form.Item name="apiBase" label="接口地址" extra="留空使用 https://drive.quark.cn/1/clouddrive"><Input placeholder="https://drive.quark.cn/1/clouddrive"/></Form.Item></>}
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
    <BaiduQrModal open={qrOpen} onClose={()=>setQrOpen(false)} onSuccess={onQrSuccess}/>
    <AliyunQrModal open={aliQrOpen} clientId={clientId} clientSecret={clientSecret} apiBase={apiBase}
      onClose={()=>setAliQrOpen(false)} onSuccess={onAliyunQrSuccess}/>
  </Modal>;
}

type QrStatus = 'loading' | 'waiting' | 'scanned' | 'expired' | 'error';

/** 百度扫码登录弹窗：轮询扫码状态，确认后把 BDUSS 交给父组件填入表单。 */
function BaiduQrModal({ open, onClose, onSuccess }: {
  open: boolean; onClose: () => void; onSuccess: (bduss: string) => void;
}) {
  const [img, setImg] = useState('');
  const [status, setStatus] = useState<QrStatus>('loading');
  const [error, setError] = useState('');
  const [epoch, setEpoch] = useState(0); // 自增触发刷新二维码

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setImg(''); setStatus('loading'); setError('');
    (async () => {
      try {
        const qr = await api.baiduQrCreate();
        if (!alive) return;
        setImg(qr.img); setStatus('waiting');
        const deadline = Date.now() + 180_000; // 与百度二维码有效期同量级
        while (alive && Date.now() < deadline) {
          const r = await api.baiduQrPoll(qr.sign, qr.gid);
          if (!alive) return;
          if (r.status === 'confirmed' && r.bduss) { onSuccess(r.bduss); return; }
          if (r.status === 'scanned') setStatus('scanned');
          if (r.status === 'expired') { setStatus('expired'); return; }
          await new Promise((resolve) => setTimeout(resolve, 1500));
        }
        if (alive) setStatus('expired');
      } catch (e) {
        if (alive) { setStatus('error'); setError(e instanceof Error ? e.message : String(e)); }
      }
    })();
    return () => { alive = false; };
  }, [open, epoch, onSuccess]);

  const stale = status === 'expired' || status === 'error';
  return <Modal title="扫码登录百度网盘" open={open} onCancel={onClose} footer={null} width={300} destroyOnHidden>
    <QrBoard src={img && `data:image/png;base64,${img}`} alt="百度登录二维码" stale={stale}
      note={status==='error'?error:'二维码已失效'} onRefresh={()=>setEpoch((n)=>n+1)}
      scanned={status==='scanned'}
      hint="用百度网盘 App 扫码，确认后自动填入 BDUSS" scannedHint="扫码成功，请在手机上点击确认登录"/>
  </Modal>;
}

/** 阿里云盘扫码授权弹窗：用表单里填的自建应用换二维码，确认后回填 refresh_token。 */
function AliyunQrModal({ open, clientId, clientSecret, apiBase, onClose, onSuccess }: {
  open: boolean; clientId: string; clientSecret: string; apiBase: string;
  onClose: () => void; onSuccess: (refreshToken: string) => void;
}) {
  const [img, setImg] = useState('');
  const [url, setUrl] = useState(''); // 服务端取图失败时退回直链
  const [status, setStatus] = useState<QrStatus>('loading');
  const [error, setError] = useState('');
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setImg(''); setUrl(''); setStatus('loading'); setError('');
    (async () => {
      try {
        const app = { clientId, clientSecret, apiBase: apiBase || undefined };
        const qr = await api.aliyunQrCreate(app);
        if (!alive) return;
        setImg(qr.img); setUrl(qr.qrCodeUrl); setStatus('waiting');
        const deadline = Date.now() + 180_000;
        while (alive && Date.now() < deadline) {
          const r = await api.aliyunQrPoll({ ...app, sid: qr.sid });
          if (!alive) return;
          if (r.status === 'confirmed' && r.refreshToken) { onSuccess(r.refreshToken); return; }
          if (r.status === 'scanned') setStatus('scanned');
          if (r.status === 'expired') { setStatus('expired'); return; }
          await new Promise((resolve) => setTimeout(resolve, 1500));
        }
        if (alive) setStatus('expired');
      } catch (e) {
        if (alive) { setStatus('error'); setError(e instanceof Error ? e.message : String(e)); }
      }
    })();
    return () => { alive = false; };
  }, [open, epoch, clientId, clientSecret, apiBase, onSuccess]);

  const stale = status === 'expired' || status === 'error';
  return <Modal title="扫码授权阿里云盘" open={open} onCancel={onClose} footer={null} width={300} destroyOnHidden>
    <QrBoard src={img ? `data:image/png;base64,${img}` : url} alt="阿里云盘授权二维码" stale={stale}
      note={status==='error'?error:'二维码已失效'} onRefresh={()=>setEpoch((n)=>n+1)}
      scanned={status==='scanned'}
      hint="用阿里云盘 App 扫码，确认后自动填入 refresh_token" scannedHint="扫码成功，请在手机上点击确认授权"/>
  </Modal>;
}

/** 二维码画面：加载中转圈、失效时盖一层刷新遮罩、底部一行状态提示。 */
function QrBoard({ src, alt, stale, note, onRefresh, scanned, hint, scannedHint }: {
  src: string; alt: string; stale: boolean; note: string; onRefresh: () => void;
  scanned: boolean; hint: string; scannedHint: string;
}) {
  return <div style={{textAlign:'center',padding:'8px 0'}}>
    <div style={{position:'relative',display:'inline-block',width:200,height:200}}>
      {src ? <img src={src} width={200} height={200} alt={alt}/> : <Spin style={{marginTop:84}}/>}
      {stale && <div style={{position:'absolute',inset:0,background:'rgba(255,255,255,.94)',display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',gap:8,padding:8}}>
        <Typography.Text type="secondary">{note}</Typography.Text>
        <Button type="primary" size="small" icon={<ReloadOutlined/>} onClick={onRefresh}>刷新二维码</Button>
      </div>}
    </div>
    <div style={{marginTop:12}}>
      <Typography.Text type={scanned?'success':'secondary'}>{scanned?scannedHint:hint}</Typography.Text>
    </div>
  </div>;
}
