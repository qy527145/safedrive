import { QrcodeOutlined, ReloadOutlined } from '@ant-design/icons';
import { App, Button, Card, Checkbox, Form, Input, Modal, QRCode, Select, Spin, Switch, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { api, type AliyunApp, type AliyunAppInput, type DsRecord, type DsType } from '../api/client';
import { useSources } from '../stores/sources';
import { parseSize, sizeToInput } from '../utils/format';

interface FormValues {
  name: string; type: DsType; root?: string; url?: string;
  username?: string; password?: string; bduss?: string; userAgent?: string;
  clientId?: string; clientSecret?: string; refreshToken?: string;
  /** 阿里云盘：内置第三方应用键，或 CUSTOM_APP */
  app?: string; webRefreshToken?: string;
  apiBase?: string; cookie?: string; encryptionEnabled: boolean;
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

/** 用户自备 client_id / client_secret 的伪应用键（与服务端一致）。 */
const CUSTOM_APP = 'custom';
/** 内置应用清单是常量表，取一次就够，弹窗反复开关不必重复请求。 */
let aliyunAppsCache: { apps: AliyunApp[]; default: string; custom: string } | null = null;

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
    case 'aliyundrive': {
      // 选了内置应用就不带自备凭据：内置应用的密钥在中转服务那边，留着
      // 上一次填的 client_id 只会在识别与刷新时添乱。
      const custom = v.app === CUSTOM_APP;
      return { root: trim(v.root), app: trim(v.app),
        clientId: custom ? trim(v.clientId) : '', clientSecret: custom ? trim(v.clientSecret) : '',
        refreshToken: trim(v.refreshToken),
        // 盘位不在此表单里配置，进数据源后用药丸随时切换：编辑时原样保留、新建默认资源库。
        driveType: editing?.config.driveType || 'resource',
        webRefreshToken: trim(v.webRefreshToken) };
    }
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
  const [aliWebQrOpen, setAliWebQrOpen] = useState(false);
  const [aliApps, setAliApps] = useState(aliyunAppsCache);
  /** 手填 refresh_token 的识别结果提示 */
  const [aliDetected, setAliDetected] = useState('');
  /** 「用官网令牌静默授权」进行中 */
  const [aliSilentLoading, setAliSilentLoading] = useState(false);
  const [form] = Form.useForm<FormValues>();
  const type = Form.useWatch('type', form) ?? 'localfs';
  const encrypted = Form.useWatch('encryptionEnabled', form) ?? true;
  const volume = Form.useWatch('volumeEnabled', form) ?? true;
  const clientId = Form.useWatch('clientId', form) ?? '';
  const clientSecret = Form.useWatch('clientSecret', form) ?? '';
  const aliApp = Form.useWatch('app', form) ?? '';
  const aliRefreshToken = Form.useWatch('refreshToken', form) ?? '';
  const aliWebRefreshToken = Form.useWatch('webRefreshToken', form) ?? '';

  useEffect(() => {
    if (!open) return;
    form.resetFields();
    setAliDetected('');
    const template = editing ?? cloneFrom;
    if (template) {
      const d = template;
      form.setFieldsValue({ name:editing?d.name:`${d.name} 副本`, type:d.type, root:d.config.root, url:d.config.url,
        username:d.config.username, password:d.config.password, bduss:d.config.bduss,
        userAgent:d.config.userAgent, clientId:d.config.clientId, clientSecret:d.config.clientSecret,
        refreshToken:d.config.refreshToken,
        // 老配置里的 app 字段可能缺失：填过 client_id 的按「自定义应用」回填。
        app:d.config.app || (d.config.clientId ? CUSTOM_APP : undefined),
        webRefreshToken:d.config.webRefreshToken,
        apiBase:d.config.apiBase, cookie:d.config.cookie,
        encryptionEnabled:d.encryptionEnabled, encryptionPassword:d.password,
        volumeEnabled:d.volumeEnabled, volumeText:sizeToInput(d.volumeSize),
        volumeStrategy:d.volumeStrategy, volumeNameFormat:d.volumeNameFormat, cacheEnabled:d.cacheEnabled });
    } else {
      form.setFieldsValue({ type: 'localfs', encryptionEnabled: true, volumeEnabled: true,
        volumeText: '300M', volumeStrategy: 'random', volumeNameFormat: '{s}_{i}.bin', cacheEnabled: true });
    }
  }, [open, editing, cloneFrom, form]);

  // 内置应用清单：进了阿里云盘表单才拉，取不到也不影响「自定义应用」。
  useEffect(() => {
    if (!open || type !== 'aliyundrive' || aliyunAppsCache) return;
    void (async () => {
      try {
        aliyunAppsCache = await api.aliyunApps();
        setAliApps(aliyunAppsCache);
      } catch { /* 下拉框只剩自定义应用，用户仍可自己填凭据 */ }
    })();
  }, [open, type]);

  // 新建时给一个默认应用（扫码默认走的就是它）。
  useEffect(() => {
    if (!open || type !== 'aliyundrive' || !aliApps) return;
    if (!trim(form.getFieldValue('app'))) form.setFieldsValue({ app: aliApps.default });
  }, [open, type, aliApps, form]);

  /**
   * refresh_token 是 JWT，交给服务端验签 + 读 `aud`：不合法/过期都如实提示，
   * 合法但认不出内置应用就降级为自定义应用，让用户自己填 client 凭据。
   */
  useEffect(() => {
    if (!open || type !== 'aliyundrive') return;
    const token = trim(aliRefreshToken);
    if (!token) { setAliDetected(''); return; }
    let alive = true;
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const r = await api.aliyunDetect(token);
          if (!alive) return;
          if (!r.valid) {
            setAliDetected('这不是有效的开放平台 refresh_token（验签未通过）；官网令牌请填到上面的「官网令牌」栏');
          } else if (r.expired) {
            setAliDetected('该 refresh_token 已过期，请重新扫码授权');
          } else if (r.app) {
            form.setFieldsValue({ app: r.app });
            setAliDetected(`已识别为「${r.name}」${r.note ? `：${r.note}` : ''}`);
          } else {
            form.setFieldsValue({ app: CUSTOM_APP });
            setAliDetected('未能识别该令牌属于哪个内置应用，请填写签发它的 client_id 与 client_secret');
          }
        } catch { /* 识别不了就保留用户当前的选择 */ }
      })();
    }, 400);
    return () => { alive = false; clearTimeout(timer); };
  }, [open, type, aliRefreshToken, form]);

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

  /** 自定义应用扫码前先确认凭据填了 —— 没有它们连二维码都换不到。 */
  const openAliyunQr = async () => {
    if (aliApp === CUSTOM_APP) {
      try { await form.validateFields(['clientId', 'clientSecret']); } catch { return; }
    }
    setAliQrOpen(true);
  };

  const onAliyunQrSuccess = useCallback((refreshToken: string, app: string) => {
    // 令牌是这个应用签发的，应用键一起落下来，刷新时才对得上 client_id。
    form.setFields([
      { name: 'refreshToken', value: refreshToken, touched: true, errors: [] },
      { name: 'app', value: app, touched: true, errors: [] },
    ]);
    setAliQrOpen(false);
    void message.success('授权成功，refresh_token 已自动填入');
  }, [form, message]);

  /**
   * 用官网令牌静默授权第三方应用，免扫码换开放平台 refresh_token。
   * `webOverride` 供刚扫完官网码时直接带值（setFields 后立即读可能取到旧值）。
   */
  const runSilentGrant = useCallback(async (webOverride?: string) => {
    const web = trim(webOverride ?? form.getFieldValue('webRefreshToken'));
    if (!web) { void message.warning('请先获取官网令牌'); return; }
    const appKey = trim(form.getFieldValue('app'));
    const custom = appKey === CUSTOM_APP;
    // 自定义应用要用用户自备凭据静默授权，先确认填了。
    if (custom) { try { await form.validateFields(['clientId', 'clientSecret']); } catch { return; } }
    const input: AliyunAppInput | undefined = appKey
      ? { app: appKey, clientId: custom ? trim(form.getFieldValue('clientId')) : undefined,
          clientSecret: custom ? trim(form.getFieldValue('clientSecret')) : undefined }
      : undefined;
    setAliSilentLoading(true);
    try {
      const r = await api.aliyunSilent(web, input);
      form.setFields([
        { name: 'refreshToken', value: r.refreshToken, touched: true, errors: [] },
        { name: 'app', value: r.app, touched: true, errors: [] },
      ]);
      void message.success(`已用官网令牌免扫码授权「${r.appName}」并填入 refresh_token`);
    } catch (e) { void message.error(e instanceof Error ? e.message : String(e)); }
    finally { setAliSilentLoading(false); }
  }, [form, message]);

  const onAliyunWebQrSuccess = useCallback((webRefreshToken: string) => {
    form.setFields([{ name: 'webRefreshToken', value: webRefreshToken, touched: true, errors: [] }]);
    setAliWebQrOpen(false);
    void message.success('登录成功，官网令牌已自动填入');
    // 顺手用它免扫码把开放平台令牌也拿了（还没有的话），省掉第二次扫码。
    if (!trim(form.getFieldValue('refreshToken'))) void runSilentGrant(webRefreshToken);
  }, [form, message, runSilentGrant]);

  const aliAppOptions = [
    ...(aliApps?.apps ?? []).map((app) => ({ label: app.name, value: app.key })),
    { label: '自定义应用（自备 client_id / client_secret）', value: CUSTOM_APP },
  ];
  const aliAppNote = aliApps?.apps.find((app) => app.key === aliApp)?.note;

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
      <Form.Item name="webRefreshToken" label="官网令牌（推荐）" extra={<><Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>setAliWebQrOpen(true)}>扫码登录官网获取</Button><div><Typography.Text type="secondary">扫码登录后可免扫码换取下方开放平台 refresh_token；分享与转存走官网 PDS 接口，必须配置官网令牌才可用。不需要分享/转存可留空。</Typography.Text></div></>}><Input.Password placeholder="扫码登录官网自动填入，可免扫码授权下方应用"/></Form.Item>
      <Form.Item name="app" label="第三方应用" extra={aliAppNote ?? '内置应用无需自建：扫码即用；填入已有 refresh_token 时会自动识别归属'}><Select options={aliAppOptions} placeholder="阿里云盘TV"/></Form.Item>
      {aliApp===CUSTOM_APP&&<><Form.Item name="clientId" label="client_id" rules={[{required:true}]} extra="阿里云盘开放平台自建应用的凭据；只在本机与阿里官方接口之间流转"><Input/></Form.Item>
      <Form.Item name="clientSecret" label="client_secret" rules={[{required:true}]}><Input.Password/></Form.Item></>}
      <Form.Item name="refreshToken" label="refresh_token" rules={[{required:true,message:'请扫码授权获取，或手动粘贴'}]} extra={<><Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>void openAliyunQr()}>扫码授权自动获取</Button>{aliWebRefreshToken&&<Button type="link" size="small" loading={aliSilentLoading} style={{padding:0,marginLeft:12}} onClick={()=>void runSilentGrant()}>用官网令牌免扫码获取</Button>}{aliDetected&&<div><Typography.Text type="secondary">{aliDetected}</Typography.Text></div>}</>}><Input.Password placeholder="点击下方扫码授权自动获取，令牌过期会自动轮换"/></Form.Item></>}
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
    <AliyunQrModal open={aliQrOpen} app={aliApp} clientId={clientId} clientSecret={clientSecret}
      onClose={()=>setAliQrOpen(false)} onSuccess={onAliyunQrSuccess}/>
    <AliyunWebQrModal open={aliWebQrOpen} onClose={()=>setAliWebQrOpen(false)} onSuccess={onAliyunWebQrSuccess}/>
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

/** 阿里云盘扫码授权弹窗：用选中的第三方应用换二维码，确认后回填 refresh_token。 */
function AliyunQrModal({ open, app: appKey, clientId, clientSecret, onClose, onSuccess }: {
  open: boolean; app: string; clientId: string; clientSecret: string;
  onClose: () => void; onSuccess: (refreshToken: string, app: string) => void;
}) {
  const [img, setImg] = useState('');
  const [url, setUrl] = useState(''); // 服务端取图失败时退回直链
  const [name, setName] = useState('');
  const [status, setStatus] = useState<QrStatus>('loading');
  const [error, setError] = useState('');
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setImg(''); setUrl(''); setName(''); setStatus('loading'); setError('');
    (async () => {
      try {
        const app = { app: appKey || undefined, clientId, clientSecret };
        const qr = await api.aliyunQrCreate(app);
        if (!alive) return;
        setImg(qr.img); setUrl(qr.qrCodeUrl); setName(qr.appName); setStatus('waiting');
        const deadline = Date.now() + 180_000;
        while (alive && Date.now() < deadline) {
          const r = await api.aliyunQrPoll({ ...app, sid: qr.sid });
          if (!alive) return;
          if (r.status === 'confirmed' && r.refreshToken) { onSuccess(r.refreshToken, r.app ?? qr.app); return; }
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
  }, [open, epoch, appKey, clientId, clientSecret, onSuccess]);

  const stale = status === 'expired' || status === 'error';
  return <Modal title="扫码授权阿里云盘" open={open} onCancel={onClose} footer={null} width={300} destroyOnHidden>
    <QrBoard src={img ? `data:image/png;base64,${img}` : url} alt="阿里云盘授权二维码" stale={stale}
      note={status==='error'?error:'二维码已失效'} onRefresh={()=>setEpoch((n)=>n+1)}
      scanned={status==='scanned'}
      hint={`用阿里云盘 App 扫码授权${name?`「${name}」`:''}，确认后自动填入 refresh_token`}
      scannedHint="扫码成功，请在手机上点击确认授权"/>
  </Modal>;
}

/**
 * 阿里云盘官网扫码登录弹窗：拿的是官网（PDS）令牌，只用于分享与转存。
 * 二维码内容是纯文本，服务端不带二维码编码器，这里本地渲染。
 */
function AliyunWebQrModal({ open, onClose, onSuccess }: {
  open: boolean; onClose: () => void; onSuccess: (webRefreshToken: string) => void;
}) {
  const [code, setCode] = useState('');
  const [status, setStatus] = useState<QrStatus>('loading');
  const [error, setError] = useState('');
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setCode(''); setStatus('loading'); setError('');
    (async () => {
      try {
        const qr = await api.aliyunWebQrCreate();
        if (!alive) return;
        setCode(qr.codeContent); setStatus('waiting');
        const deadline = Date.now() + 180_000;
        while (alive && Date.now() < deadline) {
          const r = await api.aliyunWebQrPoll(qr.session);
          if (!alive) return;
          if (r.status === 'confirmed' && r.webRefreshToken) { onSuccess(r.webRefreshToken); return; }
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
  return <Modal title="扫码登录阿里云盘官网" open={open} onCancel={onClose} footer={null} width={300} destroyOnHidden>
    <QrBoard code={code} alt="阿里云盘官网登录二维码" stale={stale}
      note={status==='error'?error:'二维码已失效'} onRefresh={()=>setEpoch((n)=>n+1)}
      scanned={status==='scanned'}
      hint="用阿里云盘 App 扫码登录，确认后自动填入官网令牌" scannedHint="扫码成功，请在手机上点击确认登录"/>
  </Modal>;
}

/** 二维码画面：加载中转圈、失效时盖一层刷新遮罩、底部一行状态提示。
 * `src` 是图片地址（上游给图），`code` 是二维码文本（本地渲染）。 */
function QrBoard({ src, code, alt, stale, note, onRefresh, scanned, hint, scannedHint }: {
  src?: string; code?: string; alt: string; stale: boolean; note: string; onRefresh: () => void;
  scanned: boolean; hint: string; scannedHint: string;
}) {
  return <div style={{textAlign:'center',padding:'8px 0'}}>
    <div style={{position:'relative',display:'inline-block',width:200,height:200}}>
      {code ? <QRCode value={code} size={200} bordered={false} style={{padding:0}}/>
        : src ? <img src={src} width={200} height={200} alt={alt}/> : <Spin style={{marginTop:84}}/>}
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
