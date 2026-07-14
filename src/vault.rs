//! 纯内存路径缓存：明文路径 → (nc, secret, dir)。
//!
//! v5.1 起没有任何本地密钥文件 —— 信封链根密钥由**策略根密码**派生
//! （strategies.json 即唯一秘密），其余密钥全部藏在云端加密名里。
//! 本缓存只是免去每次请求从根 list+解名下钻的性能设施：不落盘、
//! 可随时重建、不一致时以云端为准（resolve 叶子现场核实）。

use std::collections::HashMap;
use std::sync::RwLock;

use crate::crypto::SECRET_LEN;

/// 缓存中的一个受管节点。
#[derive(Debug, Clone)]
pub struct CachedNode {
    /// 节点秘密：文件为内容密码，目录为其 FK。
    pub secret: [u8; SECRET_LEN],
    /// 存储端密文名。
    pub nc: String,
    pub dir: bool,
}

#[derive(Default)]
pub struct PathCache {
    /// "dsId:明文全路径" → 节点
    inner: RwLock<HashMap<String, CachedNode>>,
}

fn key_of(ds: &str, path: &str) -> String {
    format!("{ds}:{path}")
}

impl PathCache {
    pub fn get(&self, ds: &str, path: &str) -> Option<CachedNode> {
        self.inner.read().unwrap().get(&key_of(ds, path)).cloned()
    }

    pub fn put(&self, ds: &str, path: &str, node: CachedNode) {
        self.inner.write().unwrap().insert(key_of(ds, path), node);
    }

    /// 失效一个前缀下的全部缓存（rename/delete/换钥后调用）。
    pub fn evict_subtree(&self, ds: &str, path: &str) {
        let mut inner = self.inner.write().unwrap();
        let exact = key_of(ds, path);
        let prefix = format!("{exact}/");
        inner.retain(|k, _| *k != exact && !k.starts_with(&prefix));
    }

    /// 数据源删除/换绑策略后清空其全部缓存。
    pub fn evict_datasource(&self, ds: &str) {
        let mut inner = self.inner.write().unwrap();
        let prefix = format!("{ds}:");
        inner.retain(|k, _| !k.starts_with(&prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::gen_secret;

    #[test]
    fn cache_ops_and_eviction() {
        let c = PathCache::default();
        let n = |nc: &str, d: bool| CachedNode { secret: gen_secret(), nc: nc.into(), dir: d };

        c.put("ds", "a", n("N1", true));
        c.put("ds", "a/b", n("N2", false));
        c.put("ds", "ab", n("N3", false));
        assert_eq!(c.get("ds", "a/b").unwrap().nc, "N2");
        assert!(c.get("ds", "缺").is_none());

        c.evict_subtree("ds", "a");
        assert!(c.get("ds", "a").is_none());
        assert!(c.get("ds", "a/b").is_none());
        assert_eq!(c.get("ds", "ab").unwrap().nc, "N3", "相邻前缀不误伤");

        c.evict_datasource("ds");
        assert!(c.get("ds", "ab").is_none());
    }
}
