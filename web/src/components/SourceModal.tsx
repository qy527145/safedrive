import { QrcodeOutlined, ReloadOutlined } from '@ant-design/icons';
import { App, Button, Card, Divider, Form, Input, Modal, QRCode, Select, Spin, Switch, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { api, type AliyunApp, type AliyunAppInput, type BaiduApp, type DsRecord, type DsType } from '../api/client';
import { useSources } from '../stores/sources';
import { parseSize, sizeToInput } from '../utils/format';

interface FormValues {
  name: string; type: DsType; root?: string; url?: string;
  username?: string; password?: string; bduss?: string; userAgent?: string;
  clientId?: string; clientSecret?: string; refreshToken?: string;
  /** 阿里云盘：内置第三方应用键，或 CUSTOM_APP */
  app?: string; webRefreshToken?: string;
  apiBase?: string; cookie?: string;
  /** 数据保护总开关：等价于「加密/分卷/伪装任一开启」，服务端据三者自行推导 */
  protectionEnabled: boolean;
  encryptionEnabled: boolean;
  encryptionPassword?: string; volumeEnabled: boolean; volumeText: string;
  volumeStrategy: 'fixed' | 'random'; leafNameFormat: string;
  disguiseEnabled: boolean; disguiseAlgorithm: string; cacheEnabled: boolean;
}

/** 叶子名模版的占位符（与服务端 crate::naming 一致）。 */
const TOKEN_SOURCE = '{s}';
const TOKEN_STEM = '{n}';
const TOKEN_EXTENSION = '{x}';
const TOKEN_ENVELOPE = '{e}';
const TOKEN_INDEX = '{i}';

/** 拆出「主名 / 扩展名」，与服务端 naming::split_extension 一致。 */
function splitExtension(source: string): [string, string] {
  const dot = source.lastIndexOf('.');
  return dot > 0 ? [source.slice(0, dot), source.slice(dot + 1)] : [source, ''];
}

/** 按模版展开一个叶子名（与服务端 naming::render 的占位符语义一致）。 */
function renderLeafName(format: string, source: string, envelope: string, index: string): string {
  const [stem, extension] = splitExtension(source);
  return format
    .split(TOKEN_SOURCE).join(source)
    .split(TOKEN_STEM).join(stem)
    .split(TOKEN_EXTENSION).join(extension)
    .split(TOKEN_ENVELOPE).join(envelope)
    .split(TOKEN_INDEX).join(index);
}

/**
 * 三个开关能推出来的默认叶子名模版（与服务端 naming::default_format 一致）：
 * 加密用 {e}（不泄露明文名），否则用 {s}；分卷再带等宽序号；开了伪装则在末尾
 * 加上算法扩展名。
 */
function defaultLeafFormat(encrypted: boolean, volume: boolean, disguise: string): string {
  const base = encrypted ? TOKEN_ENVELOPE : volume ? `${TOKEN_SOURCE}.${TOKEN_INDEX}` : TOKEN_SOURCE;
  const extension = DISGUISE_EXTENSIONS[disguise];
  return extension ? `${base}.${extension}` : base;
}

/** 模版校验，规则与服务端 naming::validate_format 一一对应。 */
function validateLeafFormat(format: string, encrypted: boolean, volume: boolean): string | null {
  if (!format.trim()) return '叶子文件名模版不能为空';
  const hasEnvelope = format.includes(TOKEN_ENVELOPE);
  const hasIndex = format.includes(TOKEN_INDEX);
  if (encrypted && !hasEnvelope) return `加密数据源的模版必须包含 ${TOKEN_ENVELOPE}（可逆索引凭据，同时避免泄露明文名）`;
  if (!encrypted && hasEnvelope) return `${TOKEN_ENVELOPE} 只在启用加密时可用`;
  if (volume && !encrypted && !hasIndex) return `未加密的分卷数据源必须包含 ${TOKEN_INDEX}，否则无法确定分卷序号`;
  if (!volume && hasIndex) return `${TOKEN_INDEX} 只在启用分卷时可用`;
  const residue = [TOKEN_SOURCE, TOKEN_STEM, TOKEN_EXTENSION, TOKEN_ENVELOPE, TOKEN_INDEX]
    .reduce((rest, token) => rest.split(token).join(''), format);
  if (residue.includes('{') || residue.includes('}')) {
    return `模版里有无法识别的占位符；只支持 ${TOKEN_SOURCE} / ${TOKEN_STEM} / ${TOKEN_EXTENSION} / ${TOKEN_ENVELOPE} / ${TOKEN_INDEX}`;
  }
  // 带扩展名与不带扩展名两种取样都得站得住：{x} 对后者展开成空。
  for (const source of ['sample.bin', 'sample']) {
    const sample = renderLeafName(format, source, 'a1', '01');
    if (sample.includes('/') || sample.includes('\\') || sample === '.' || sample === '..') {
      return '模版展开后包含非法路径字符';
    }
    if (!sample) {
      return `模版对没有扩展名的文件会展开成空名字；请至少再带上 ${TOKEN_STEM} / ${TOKEN_SOURCE} / ${TOKEN_ENVELOPE} / ${TOKEN_INDEX} 或固定文字`;
    }
  }
  return null;
}

/** 预览用的示例文件名与凭据取样。 */
const PREVIEW_SOURCE = '电影.mkv';
const PREVIEW_ENVELOPE = ['3f', 'a1', 'c8'];

/**
 * 按模版展开出示例叶子名。带 {i} 或 {e} 时给三个（能看出序号/凭据怎么变），
 * 否则一个就够。
 */
function previewLeafNames(format: string): string[] {
  const count = format.includes(TOKEN_INDEX) || format.includes(TOKEN_ENVELOPE) ? 3 : 1;
  return Array.from({ length: count }, (_, i) =>
    renderLeafName(format, PREVIEW_SOURCE, PREVIEW_ENVELOPE[i], String(i + 1).padStart(2, '0')),
  );
}

const DS_TYPES: { label: string; value: DsType }[] = [
  { label: '本地文件系统', value: 'localfs' },
  { label: 'WebDAV', value: 'webdav' },
  { label: '百度网盘', value: 'baidupan' },
  { label: '阿里云盘', value: 'aliyundrive' },
  { label: '夸克网盘', value: 'quark' },
];

/** 伪装算法下拉表（与服务端 disguise::ALGORITHMS 一致，默认取第一项）。 */
const DISGUISE_ALGORITHMS = [
  { label: 'BMP 位图（54 字节标准头部）', value: 'bmp' },
];
/** 各算法对应的叶子名扩展名（与服务端 Disguise::extension 一致）。 */
const DISGUISE_EXTENSIONS: Record<string, string | undefined> = { bmp: 'bmp' };

/** 用户自备 client_id / client_secret 的伪应用键（与服务端一致）。 */
const CUSTOM_APP = 'custom';
/** 内置应用清单是常量表，取一次就够，弹窗反复开关不必重复请求。 */
let aliyunAppsCache: { apps: AliyunApp[]; default: string; custom: string } | null = null;
let baiduAppsCache: { apps: BaiduApp[]; default: string; custom: string } | null = null;

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
      // 选了内置应用（默认 ES 文件管理器）就不带自备凭据，只有自定义应用才回填。
      // 根目录留空即网盘根目录（与阿里云盘、夸克网盘一致），不再强塞 /safedrive。
      return { root: trim(v.root), bduss: trim(v.bduss) || trim(editing?.config.bduss),
        userAgent: v.userAgent ?? '', app: trim(v.app),
        clientId: v.app === CUSTOM_APP ? trim(v.clientId) : '',
        clientSecret: v.app === CUSTOM_APP ? trim(v.clientSecret) : '' };
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
  const [baiduApps, setBaiduApps] = useState(baiduAppsCache);
  /** 手填 refresh_token 的识别结果提示 */
  const [aliDetected, setAliDetected] = useState('');
  /** 「用官网令牌静默授权」进行中 */
  const [aliSilentLoading, setAliSilentLoading] = useState(false);
  const [form] = Form.useForm<FormValues>();
  const type = Form.useWatch('type', form) ?? 'localfs';
  // 数据保护总开关。服务端没有这个字段 —— 它就是「加密/分卷/伪装任一开启」，
  // 关掉即三者全关。开启后文件落进由根密码加密命名的信封目录，于是根密码与
  // 叶子名模版成了三者共用的配置。
  const protection = Form.useWatch('protectionEnabled', form) ?? true;
  const encrypted = (Form.useWatch('encryptionEnabled', form) ?? true) && protection;
  const volume = (Form.useWatch('volumeEnabled', form) ?? true) && protection;
  const disguised = (Form.useWatch('disguiseEnabled', form) ?? false) && protection;
  const disguiseAlgorithm = Form.useWatch('disguiseAlgorithm', form) ?? DISGUISE_ALGORITHMS[0].value;
  const leafFormat = Form.useWatch('leafNameFormat', form) ?? '';
  const clientId = Form.useWatch('clientId', form) ?? '';
  const clientSecret = Form.useWatch('clientSecret', form) ?? '';
  // `app` 字段由阿里云盘与百度网盘共用（同一时刻只有一种类型在编辑）。
  const selectedApp = Form.useWatch('app', form) ?? '';
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
        volumeStrategy:d.volumeStrategy, leafNameFormat:d.leafNameFormat,
        disguiseEnabled:d.disguiseEnabled, disguiseAlgorithm:d.disguiseAlgorithm || DISGUISE_ALGORITHMS[0].value,
        // 服务端不存这个开关，按三者是否有开的推回来。
        protectionEnabled:d.encryptionEnabled || d.volumeEnabled || d.disguiseEnabled,
        cacheEnabled:d.cacheEnabled });
    } else {
      form.setFieldsValue({ type: 'localfs', protectionEnabled: true,
        encryptionEnabled: true, volumeEnabled: true,
        volumeText: '300M', volumeStrategy: 'random',
        leafNameFormat: defaultLeafFormat(true, true, ''),
        disguiseEnabled: false, disguiseAlgorithm: DISGUISE_ALGORITHMS[0].value, cacheEnabled: true });
    }
  }, [open, editing, cloneFrom, form]);

  // 新建时开关一动就把叶子名模版重置成该组合的默认值：既省得用户手填，也
  // 避免留下一个与新开关不自洽的模版（如关掉加密后还剩着 {e}）。编辑时不动
  // —— 模版创建后不可更改。
  useEffect(() => {
    if (!open || editing) return;
    form.setFieldsValue({
      leafNameFormat: defaultLeafFormat(encrypted, volume, disguised ? disguiseAlgorithm : ''),
    });
  }, [open, editing, encrypted, volume, disguised, disguiseAlgorithm, form]);

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

  // 新建时给一个默认应用（扫码默认走的就是它）。`app` 字段被阿里云盘与百度
  // 网盘共用，切换类型时上一家的选中值会残留（如百度冒出 tv、阿里冒出 es），
  // 所以要判断当前值是否属于本家：不属于就重置为本家默认。
  useEffect(() => {
    if (!open || type !== 'aliyundrive' || !aliApps) return;
    const cur = trim(form.getFieldValue('app'));
    const known = cur === CUSTOM_APP || aliApps.apps.some((app) => app.key === cur);
    if (!known) form.setFieldsValue({ app: aliApps.default });
  }, [open, type, aliApps, form]);

  // 百度网盘内置应用清单：进了百度表单才拉，取不到也不影响「自定义应用」。
  useEffect(() => {
    if (!open || type !== 'baidupan' || baiduAppsCache) return;
    void (async () => {
      try {
        baiduAppsCache = await api.baiduApps();
        setBaiduApps(baiduAppsCache);
      } catch { /* 下拉框只剩自定义应用，用户仍可自己填凭据 */ }
    })();
  }, [open, type]);

  // 新建百度网盘时给一个默认应用（默认 ES 文件管理器）；同样要挡住阿里那边残留的选中值。
  useEffect(() => {
    if (!open || type !== 'baidupan' || !baiduApps) return;
    const cur = trim(form.getFieldValue('app'));
    const known = cur === CUSTOM_APP || baiduApps.apps.some((app) => app.key === cur);
    if (!known) form.setFieldsValue({ app: baiduApps.default });
  }, [open, type, baiduApps, form]);

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
    // 总开关只是前端的分组：关掉即三者全关，服务端据三者推导「是否受管」。
    const on = v.protectionEnabled;
    const enc = on && v.encryptionEnabled;
    const vol = on && v.volumeEnabled;
    const dis = on && v.disguiseEnabled;
    if (on && !enc && !vol && !dis) {
      message.error('启用数据保护后，至少要开启内容加密、分卷存储、存储侧伪装中的一项');
      return;
    }
    const config = buildConfig(v, editing);
    const body = {name:v.name,type:v.type,config,encryptionEnabled:enc,
      password:on ? (v.encryptionPassword || undefined) : undefined,volumeEnabled:vol,
      volumeSize:vol ? parseSize(v.volumeText) ?? 0 : 0,volumeStrategy:v.volumeStrategy,
      leafNameFormat:on ? v.leafNameFormat : undefined,disguiseEnabled:dis,
      disguiseAlgorithm:v.disguiseAlgorithm || DISGUISE_ALGORITHMS[0].value,cacheEnabled:v.cacheEnabled};
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
    if (selectedApp === CUSTOM_APP) {
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
  const aliAppNote = aliApps?.apps.find((app) => app.key === selectedApp)?.note;
  const baiduAppOptions = [
    ...(baiduApps?.apps ?? []).map((app) => ({ label: app.name, value: app.key })),
    { label: '自定义应用（自备 API Key / Secret Key）', value: CUSTOM_APP },
  ];
  const baiduAppNote = baiduApps?.apps.find((app) => app.key === selectedApp)?.note;

  return <Modal title={editing?'编辑数据源':cloneFrom?'克隆数据源':'添加数据源'} open={open} confirmLoading={saving} onOk={()=>void onSubmit()} onCancel={confirmClose} destroyOnHidden width={620}>
    <Form form={form} layout="vertical" name="ds">
      <Form.Item name="name" label="数据源名称" tooltip="仅用于本机识别，同时是 WebDAV 路径的一段（/dav/<数据源名>/…）。随时可改。" rules={[{required:true}]}><Input/></Form.Item>
      <Form.Item name="type" label="类型" tooltip="存储后端。本地文件系统与 WebDAV 直连，三家网盘走各自的官方/官网接口。创建后不可更改。" rules={[{required:true}]}><Select disabled={!!editing} options={DS_TYPES}/></Form.Item>
      {type==='localfs'&&<Form.Item name="root" label="根目录" tooltip="服务端本机的绝对路径，SafeDrive 只在该目录内读写；目录不存在会自动创建。" rules={[{required:true}]}><Input/></Form.Item>}
      {type==='webdav'&&<><Form.Item name="url" label="WebDAV 地址" tooltip="WebDAV 服务的完整地址，必须以 http:// 或 https:// 开头，可带子路径（如 /remote.php/dav）。" rules={[{required:true},{pattern:/^https?:\/\//}]}><Input/></Form.Item><Form.Item name="username" label="用户名" tooltip="WebDAV Basic 认证用户名；服务端免鉴权时可留空。"><Input/></Form.Item><Form.Item name="password" label="密码" tooltip="WebDAV Basic 认证密码；只存在本机 datasources.json 里。"><Input.Password/></Form.Item></>}
      {type==='baidupan'&&<><Form.Item name="root" label="网盘根目录" tooltip="SafeDrive 在该网盘里的工作目录，所有读写都限定在它之内。留空即网盘根目录；建议单独用一个目录，便于与网盘里的其它文件隔离。"><Input placeholder="/safedrive"/></Form.Item>
      <Form.Item name="bduss" label="BDUSS" tooltip="百度账号的登录凭证（浏览器 Cookie 里的 BDUSS 字段），用于下载与分享等网页接口。推荐用扫码登录自动获取，免去手动翻 Cookie。" rules={[{required:true,message:'请扫码登录获取，或手动粘贴'}]} extra={<Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>setQrOpen(true)}>扫码登录自动获取</Button>}><Input.Password placeholder="点击下方扫码登录自动获取，或手动粘贴 Cookie 中的 BDUSS"/></Form.Item>
      <Form.Item name="app" label="第三方应用" tooltip="用哪个开放平台应用来读写文件。内置应用无需自建，扫码拿到 BDUSS 后会自动完成设备授权换取令牌；也可改选「自定义应用」填自己申请的凭据。" extra={baiduAppNote}><Select options={baiduAppOptions} placeholder="ES 文件管理器"/></Form.Item>
      {selectedApp===CUSTOM_APP&&<><Form.Item name="clientId" label="API Key（client_id）" tooltip="百度网盘开放平台自建应用的 API Key；只在本机与百度官方接口之间流转。" rules={[{required:true}]}><Input/></Form.Item>
      <Form.Item name="clientSecret" label="Secret Key（client_secret）" tooltip="与 API Key 配对的 Secret Key，必须同时填写。" rules={[{required:true}]}><Input.Password/></Form.Item></>}
      <Form.Item name="userAgent" label="下载 User-Agent" tooltip="发起下载请求时使用的 UA 标识。留空使用默认值；个别网络环境下换一个 UA 能改善下载速度。" ><Input placeholder="netdisk;P2SP;2.2.61.31;android"/></Form.Item></>}
      {type==='aliyundrive'&&<><Form.Item name="root" label="网盘根目录" tooltip="SafeDrive 在该网盘里的工作目录，所有读写都限定在它之内。留空即网盘根目录；建议单独用一个目录。"><Input placeholder="/safedrive"/></Form.Item>
      <Form.Item name="webRefreshToken" label="官网令牌（推荐）" tooltip="阿里云盘官网（PDS）令牌。一份顶两用：可免扫码换取下方开放平台 refresh_token；分享与转存只能走官网接口，不配置就没有分享入口。不需要分享/转存可留空。" extra={<Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>setAliWebQrOpen(true)}>扫码登录官网获取</Button>}><Input.Password placeholder="扫码登录官网自动填入，可免扫码授权下方应用"/></Form.Item>
      <Form.Item name="app" label="第三方应用" tooltip="日常读写走开放平台，需要一个应用的凭据。内置应用无需自建、扫码即用；填入已有 refresh_token 时会按签发者自动识别归属。也可改选「自定义应用」填自己申请的凭据。" extra={aliAppNote}><Select options={aliAppOptions} placeholder="阿里云盘TV"/></Form.Item>
      {selectedApp===CUSTOM_APP&&<><Form.Item name="clientId" label="client_id" tooltip="阿里云盘开放平台自建应用的 client_id；只在本机与阿里官方接口之间流转。" rules={[{required:true}]}><Input/></Form.Item>
      <Form.Item name="clientSecret" label="client_secret" tooltip="与 client_id 配对的密钥，必须同时填写。" rules={[{required:true}]}><Input.Password/></Form.Item></>}
      <Form.Item name="refreshToken" label="refresh_token" tooltip="开放平台长期令牌，日常读写都靠它换取 access token（到期自动轮换并写回配置）。可扫码授权获取，或用上面的官网令牌免扫码获取。" rules={[{required:true,message:'请扫码授权获取，或手动粘贴'}]} extra={<><Button type="link" size="small" icon={<QrcodeOutlined/>} style={{padding:0}} onClick={()=>void openAliyunQr()}>扫码授权自动获取</Button>{aliWebRefreshToken&&<Button type="link" size="small" loading={aliSilentLoading} style={{padding:0,marginLeft:12}} onClick={()=>void runSilentGrant()}>用官网令牌免扫码获取</Button>}{aliDetected&&<div><Typography.Text type="secondary">{aliDetected}</Typography.Text></div>}</>}><Input.Password placeholder="点击下方扫码授权自动获取，令牌过期会自动轮换"/></Form.Item></>}
      {type==='quark'&&<><Form.Item name="root" label="网盘根目录" tooltip="SafeDrive 在该网盘里的工作目录，所有读写都限定在它之内。留空即网盘根目录；建议单独用一个目录。"><Input placeholder="/safedrive"/></Form.Item>
      <Form.Item name="cookie" label="Cookie" tooltip="浏览器登录 pan.quark.cn 后复制的整串 Cookie，必须包含 __puus。__puus 会不断轮换，后台自动续期并写回配置，同一份填一次即可长期使用。" rules={[{required:true}]}><Input.TextArea rows={3} autoComplete="off" placeholder="__pus=...; __puus=...; ..."/></Form.Item>
      <Form.Item name="apiBase" label="接口地址" tooltip="夸克网盘 API 域名，一般不用改。留空使用 https://drive.quark.cn/1/clouddrive。"><Input placeholder="https://drive.quark.cn/1/clouddrive"/></Form.Item></>}
      <Form.Item name="cacheEnabled" label="持久下载缓存" valuePropName="checked"
        tooltip="允许该数据源把云端密文按 1 MiB 块缓存到本地磁盘，命中后不再回源，重复播放/下载更快。还受设置页的全局缓存总开关约束。随时可改。">
        <Switch/>
      </Form.Item>
      <Card size="small" title="数据保护" style={{marginBottom:16}}>
        <Form.Item name="protectionEnabled" label="启用数据保护" valuePropName="checked"
          tooltip="开启后每个文件在存储端落进一个由根密码加密命名的「信封目录」，可按需叠加内容加密 / 分卷存储 / 存储侧伪装；关闭则原样存明文文件。该选择创建后不可更改。"
          extra={editing?'创建后不可修改；如需切换请新建数据源。':undefined}>
          <Switch disabled={!!editing}/>
        </Form.Item>
        {protection&&<>
          <Form.Item name="encryptionPassword" label="根密码" rules={[{required:!editing,message:'请输入密码'}]}
            tooltip="整个数据源的主密钥。信封目录名与内容加密密钥都由它派生，同时是「这个存储对象是不是 SafeDrive 写的」的唯一判据。丢失后无法恢复数据，请另行备份。"
            extra={editing?'修改后会重命名存储端根层加密文件名；留空保持原密码。':undefined}>
            <Input.Password/>
          </Form.Item>
          <Form.Item name="leafNameFormat" label="叶子文件名模版" rules={[{required:true},{validator:(_,v:string)=>{const error=validateLeafFormat(v??'',encrypted,volume);return error?Promise.reject(new Error(error)):Promise.resolve();}}]}
            tooltip={`信封目录里每个叶子对象的名字。${TOKEN_SOURCE} 原始文件名（含扩展名）、${TOKEN_STEM} 主名（不含扩展名）、${TOKEN_EXTENSION} 原扩展名、${TOKEN_ENVELOPE} 文件密钥派生的可逆索引凭据（加密时必填，且不泄露明文名）、${TOKEN_INDEX} 等宽分卷序号（未加密分卷时必填）。创建后不可修改。`}
            extra={<>
              <div>可用占位符：{TOKEN_SOURCE} 原文件名、{TOKEN_STEM} 主名（不含扩展名）、{TOKEN_EXTENSION} 扩展名{encrypted&&<>、{TOKEN_ENVELOPE} 索引凭据</>}{volume&&<>、{TOKEN_INDEX} 分卷序号</>}。{editing&&'创建后不可修改。'}</div>
              {!validateLeafFormat(leafFormat,encrypted,volume)&&
                <div style={{marginTop:4,display:'flex',flexWrap:'wrap',gap:6,alignItems:'baseline'}}>
                  <span>示例（原文件名 {PREVIEW_SOURCE}）：</span>
                  {previewLeafNames(leafFormat).map((name,index)=>
                    <Typography.Text key={index} code>{name}</Typography.Text>)}
                </div>}
            </>}>
            <Input disabled={!!editing} placeholder={defaultLeafFormat(encrypted,volume,disguised?disguiseAlgorithm:'')}/>
          </Form.Item>
          <Divider style={{margin:'0 0 16px'}}/>
          <Form.Item name="encryptionEnabled" label="内容加密" valuePropName="checked"
            tooltip="文件内容过 ChaCha20 加密；密文长度与明文相同，不影响任何大小计算。开启后叶子名模版必须用 {e}，云端连文件名都看不到。创建后不可修改。"
            extra={editing?'创建后不可修改。':undefined}>
            <Switch disabled={!!editing}/>
          </Form.Item>
          <Divider style={{margin:'0 0 16px'}}/>
          <Form.Item name="volumeEnabled" label="分卷存储" valuePropName="checked"
            tooltip="把一个文件切成多个叶子对象落地，绕开网盘的单文件大小限制。是否分卷创建后不可修改，但分卷大小与固定/随机策略之后可调。"
            extra={editing?'创建后不可修改；最大分卷大小与固定/随机策略之后可调。':undefined}>
            <Switch disabled={!!editing}/>
          </Form.Item>
          {volume&&<>
            <Form.Item name="volumeText" label="最大分卷大小" rules={[{required:true},{validator:(_,v)=>{const n=parseSize(v??'');return n!=null&&n>=64*1024?Promise.resolve():Promise.reject(new Error('至少 64K，例如 300M'));}}]}
              tooltip="单个落地对象的字节上限，支持 K/M/G 单位（至少 64K）。开了伪装时每个对象要多带 54 字节头部，数据区上限会自动缩到该值减 54。随时可改，只影响之后上传的文件。">
              <Input/>
            </Form.Item>
            <Form.Item name="volumeStrategy" label="分卷策略"
              tooltip="随机大小：每卷在上限附近随机取值，卷数与固定策略一致，但落地大小不呈规律。固定大小：除最后一卷外都正好是上限。随时可改。">
              <Select options={[{label:'随机大小（默认，卷数与固定策略一致）',value:'random'},{label:'固定大小',value:'fixed'}]}/>
            </Form.Item>
          </>}
          <Divider style={{margin:'0 0 16px'}}/>
          <Form.Item name="disguiseEnabled" label="存储侧伪装" valuePropName="checked"
            tooltip="给每个落地对象套一层伪装头部（分卷则每个卷各一份），云端看到的是一个格式合法的普通文件。同时开了加密则先加密再伪装。创建后不可修改。"
            extra={editing?'创建后不可修改。':undefined}>
            <Switch disabled={!!editing}/>
          </Form.Item>
          {disguised&&<Form.Item name="disguiseAlgorithm" label="伪装算法" rules={[{required:true}]}
            tooltip="按文件大小动态生成标准的 54 字节 BMP 头部；默认模版会补上 .bmp 后缀，云端看到的连名字带内容都像一张位图。创建后不可修改。"
            extra={editing?'创建后不可修改。':undefined}>
            <Select disabled={!!editing} options={DISGUISE_ALGORITHMS}/>
          </Form.Item>}
        </>}
      </Card>
    </Form>
    <BaiduQrModal open={qrOpen} onClose={()=>setQrOpen(false)} onSuccess={onQrSuccess}/>
    <AliyunQrModal open={aliQrOpen} app={selectedApp} clientId={clientId} clientSecret={clientSecret}
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
