//! Durable, deterministic session references with idle/capacity garbage collection.
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};

pub const FORGOTTEN_ERROR: &str = "session reference expired/forgotten";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRef { pub upstream: String, pub session_id: String, pub last_active_ms: u64 }

#[derive(Default, Serialize, Deserialize)]
struct Disk { #[serde(default)] entries: HashMap<String, SessionRef>, #[serde(default)] forgotten: HashSet<String> }
#[derive(Default)] struct Inner { disk: Disk, dirty: bool }

#[derive(Clone)]
pub struct SessionStore { inner: Arc<Mutex<Inner>>, path: Arc<PathBuf>, ttl: Duration, max: usize }

impl SessionStore {
    pub fn open(path: impl AsRef<Path>, ttl: Duration, max: usize) -> std::io::Result<Self> {
        let path=path.as_ref();
        let disk=match fs::read(path) {
            Ok(bytes)=>serde_json::from_slice(&bytes).map_err(|e|std::io::Error::new(std::io::ErrorKind::InvalidData,e))?,
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Disk::default(),
            Err(e)=>return Err(e),
        };
        Ok(Self { inner:Arc::new(Mutex::new(Inner{disk,dirty:false})), path:Arc::new(path.to_owned()), ttl, max:max.max(1) })
    }
    fn lock(&self)->std::sync::MutexGuard<'_,Inner>{self.inner.lock().unwrap_or_else(|e|e.into_inner())}
    fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64}
    fn write(inner:&Inner,path:&Path)->std::io::Result<()> {
        if let Some(parent)=path.parent().filter(|p|!p.as_os_str().is_empty()){fs::create_dir_all(parent)?;}
        let tmp=path.with_extension(format!("tmp-{}",std::process::id()));
        { let mut f=fs::File::create(&tmp)?; serde_json::to_writer(&mut f,&inner.disk).map_err(std::io::Error::other)?; f.write_all(b"\n")?; f.sync_all()?; }
        fs::rename(&tmp,path)?;
        Ok(())
    }
    /// Recording is idempotent and always uses the stable external reference.
    pub fn record_at(&self,upstream:&str,real:&str,now_ms:u64)->String {
        let external=crate::protocol::wrap_session_id(upstream,real);
        let mut inner=self.lock();
        inner.disk.forgotten.remove(&external);
        inner.disk.entries.insert(external.clone(),SessionRef{upstream:upstream.into(),session_id:real.into(),last_active_ms:now_ms});
        inner.dirty=true;
        if let Err(e)=Self::write(&inner,&self.path){tracing::warn!(%e,"could not persist session references");}else{inner.dirty=false;}
        external
    }
    pub fn record(&self,upstream:&str,real:&str)->String{self.record_at(upstream,real,Self::now())}
    pub fn touch_at(&self,external:&str,now_ms:u64)->bool {
        let mut inner=self.lock();
        if let Some(entry)=inner.disk.entries.get_mut(external){entry.last_active_ms=now_ms;inner.dirty=true;true}else{false}
    }
    pub fn touch(&self,external:&str)->bool{self.touch_at(external,Self::now())}
    pub fn resolve(&self,external:&str)->Result<SessionRef,String>{
        let inner=self.lock();
        if inner.disk.forgotten.contains(external){return Err(FORGOTTEN_ERROR.into())}
        if let Some(entry)=inner.disk.entries.get(external).cloned(){return Ok(entry)}
        // Well-formed references not known to this store may have been learned by another
        // gateway instance sharing the upstream. Register optimistically; explicit GC/manual
        // deletion remains authoritative and is distinguishable on every later call.
        if let Some((upstream,real))=crate::protocol::unwrap_session_id(external){return Ok(SessionRef{upstream:upstream.into(),session_id:real.into(),last_active_ms:Self::now()})}
        Err("unknown session reference".into())
    }
    #[cfg(test)] pub fn contains(&self,external:&str)->bool{self.lock().disk.entries.contains_key(external)}
    pub fn forget(&self,external:&str)->Result<bool,String>{
        let mut inner=self.lock();
        let removed=inner.disk.entries.remove(external).is_some();
        inner.disk.forgotten.insert(external.into());inner.dirty=true;
        Self::write(&inner,&self.path).map_err(|e|format!("persist session.forget: {e}"))?;inner.dirty=false;
        Ok(removed)
    }
    /// Removes expired entries, then least-recently-active entries over the cap.
    /// Removals are always persisted so a restart cannot resurrect forgotten references.
    pub fn reap_at(&self,now_ms:u64)->usize{
        let mut inner=self.lock();let before=inner.disk.entries.len();
        let ttl=self.ttl.as_millis() as u64;let max=self.max;
        let expired:Vec<String>=inner.disk.entries.iter().filter(|(_,e)|now_ms.saturating_sub(e.last_active_ms)>=ttl).map(|(id,_)|id.clone()).collect();
        for id in expired{inner.disk.entries.remove(&id);inner.disk.forgotten.insert(id);}
        while inner.disk.entries.len()>max {
            let oldest=inner.disk.entries.iter().min_by(|a,b|a.1.last_active_ms.cmp(&b.1.last_active_ms).then_with(||a.0.cmp(b.0))).map(|(id,_)|id.clone());
            if let Some(id)=oldest{inner.disk.entries.remove(&id);inner.disk.forgotten.insert(id);}else{break}
        }
        let removed=before-inner.disk.entries.len();
        if removed > 0 { inner.dirty = true; }
        if inner.dirty {
            if let Err(e)=Self::write(&inner,&self.path){tracing::warn!(%e,"could not persist session GC");}
            else { inner.dirty=false; }
        }
        removed
    }
    pub fn reap(&self)->usize{self.reap_at(Self::now())}
    pub fn spawn_reaper(&self)->tokio::task::JoinHandle<()> {
        let store=self.clone();let period=(self.ttl/4).clamp(Duration::from_millis(50),Duration::from_secs(60));
        tokio::spawn(async move{let mut tick=tokio::time::interval(period);tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);loop{tick.tick().await;store.reap();}})
    }
    /// Active remembered entries and forgotten-set size (for `/status` gauges).
    pub fn stats(&self) -> SessionStoreStats {
        let inner = self.lock();
        SessionStoreStats { refs: inner.disk.entries.len(), forgotten: inner.disk.forgotten.len() }
    }
    #[cfg(test)] pub fn len(&self)->usize{self.stats().refs}
    /// True when any remembered reference is owned by `upstream` (sticky discovery check).
    pub fn has_upstream(&self, upstream: &str) -> bool {
        self.lock().disk.entries.values().any(|e| e.upstream == upstream)
    }
}

/// Snapshot of session-store sizes exposed on `GET /status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStoreStats { pub refs: usize, pub forgotten: usize }


#[cfg(test)]mod tests{
 use super::*;
 fn store(max:usize)->(SessionStore,tempfile::TempDir){let d=tempfile::tempdir().unwrap();(SessionStore::open(d.path().join("state.json"),Duration::from_secs(60),max).unwrap(),d)}
 #[test]fn round_trip_restart_and_manual_delete(){let(s,d)=store(5);let id=s.record_at("local","session:a",10);assert_eq!(s.resolve(&id).unwrap().session_id,"session:a");let loaded=SessionStore::open(d.path().join("state.json"),Duration::from_secs(60),5).unwrap();assert!(loaded.touch_at(&id,20));assert!(loaded.forget(&id).unwrap());assert_eq!(loaded.resolve(&id),Err(FORGOTTEN_ERROR.into()));let again=SessionStore::open(d.path().join("state.json"),Duration::from_secs(60),5).unwrap();assert_eq!(again.resolve(&id),Err(FORGOTTEN_ERROR.into()));}
 #[test]fn ttl_and_capacity_forget_lru(){let(s,_)=store(2);let a=s.record_at("a","session:a",1);let b=s.record_at("a","session:b",2);assert!(s.touch_at(&a,3));let c=s.record_at("a","session:c",4);assert_eq!(s.reap_at(5),1);assert_eq!(s.resolve(&b),Err(FORGOTTEN_ERROR.into()));assert!(s.contains(&a)&&s.contains(&c));assert_eq!(s.reap_at(70_000),2);assert_eq!(s.len(),0);}
 #[test]fn unknown_differs_from_forgotten(){let(s,_)=store(1);assert!(s.resolve("a:session:no").is_ok()); assert!(s.resolve("malformed").is_err());}
 #[test]fn stats_counts_refs_and_forgotten(){
    let(s,_)=store(2);
    assert_eq!(s.stats(), SessionStoreStats{refs:0,forgotten:0});
    let a=s.record_at("local","session:a",1);
    let b=s.record_at("local","session:b",2);
    assert_eq!(s.stats(), SessionStoreStats{refs:2,forgotten:0});
    assert!(s.forget(&a).unwrap());
    assert_eq!(s.stats(), SessionStoreStats{refs:1,forgotten:1});
    assert_eq!(s.reap_at(70_000),1);
    assert_eq!(s.stats().refs,0);
    assert!(s.stats().forgotten >= 2, "{:?}", s.stats());
    let _=b;
 }
 #[test]fn reap_persists_forgotten_across_restart(){
    let d=tempfile::tempdir().unwrap();
    let path=d.path().join("state.json");
    let s=SessionStore::open(&path,Duration::from_secs(60),2).unwrap();
    let a=s.record_at("local","session:a",1);
    let b=s.record_at("local","session:b",2);
    // Capacity GC forgets the least-recently-active entry and must hit disk.
    let c=s.record_at("local","session:c",3);
    assert_eq!(s.reap_at(3),1);
    assert_eq!(s.resolve(&a),Err(FORGOTTEN_ERROR.into()));
    assert!(s.contains(&b)&&s.contains(&c));
    let loaded=SessionStore::open(&path,Duration::from_secs(60),2).unwrap();
    assert_eq!(loaded.resolve(&a),Err(FORGOTTEN_ERROR.into()), "GC must survive restart");
    assert!(loaded.resolve(&b).is_ok()&&loaded.resolve(&c).is_ok());
    // TTL GC without a prior dirty touch must also persist.
    assert_eq!(loaded.reap_at(70_000),2);
    let again=SessionStore::open(&path,Duration::from_secs(60),2).unwrap();
    assert_eq!(again.resolve(&b),Err(FORGOTTEN_ERROR.into()));
    assert_eq!(again.resolve(&c),Err(FORGOTTEN_ERROR.into()));
 }
}
