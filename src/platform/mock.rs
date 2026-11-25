//! In-memory fake process for unit tests.

use std::sync::RwLock;

use super::{Arch, Module, ProcessMemory, Protection, Region, RegionKind, RegionState};
use crate::error::{MemError, Result};

pub struct MockProcess {
    arch: Arch,
    segments: RwLock<Vec<(u64, Vec<u8>)>>,
    modules: Vec<Module>,
}

impl MockProcess {
    pub fn new(arch: Arch) -> Self {
        Self { arch, segments: RwLock::new(Vec::new()), modules: Vec::new() }
    }

    pub fn map(&mut self, base: u64, bytes: Vec<u8>) {
        let segs = self.segments.get_mut().unwrap();
        segs.push((base, bytes));
        segs.sort_by_key(|s| s.0);
    }

    pub fn add_module(&mut self, name: &str, base: u64, image: Vec<u8>) {
        self.modules.push(Module {
            name: name.into(),
            path: format!("C:\\mock\\{name}"),
            base,
            size: image.len() as u64,
            arch: Some(self.arch),
        });
        self.modules.sort_by_key(|m| m.base);
        self.map(base, image);
    }

    /// Writes a pointer-sized value.
    pub fn put_ptr(&self, addr: u64, v: u64) {
        let bytes = if self.arch.pointer_size() == 4 { (v as u32).to_le_bytes().to_vec() } else { v.to_le_bytes().to_vec() };
        self.write(addr, &bytes).unwrap();
    }

    fn locate(&self, addr: u64, len: usize) -> Option<(usize, usize)> {
        let segs = self.segments.read().unwrap();
        segs.iter().enumerate().find_map(|(i, (b, d))| {
            (addr >= *b && addr + len as u64 <= b + d.len() as u64).then(|| (i, (addr - b) as usize))
        })
    }
}

impl ProcessMemory for MockProcess {
    fn pid(&self) -> u32 {
        1234
    }
    fn name(&self) -> &str {
        "mock.exe"
    }
    fn image_path(&self) -> Option<String> {
        None
    }
    fn arch(&self) -> Arch {
        self.arch
    }
    fn is_alive(&self) -> bool {
        true
    }
    fn can_write(&self) -> bool {
        true
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        match self.locate(addr, buf.len()) {
            Some((i, off)) => {
                let segs = self.segments.read().unwrap();
                buf.copy_from_slice(&segs[i].1[off..off + buf.len()]);
                Ok(())
            }
            None => Err(MemError::Read { addr, size: buf.len(), reason: self.explain_unreadable(addr) }),
        }
    }

    /// Byte-granular (mock segments may be smaller than a page).
    fn read_partial(&self, addr: u64, len: usize) -> Vec<Option<u8>> {
        (0..len as u64)
            .map(|i| {
                let mut b = [0u8; 1];
                self.read(addr + i, &mut b).ok().map(|_| b[0])
            })
            .collect()
    }

    fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        match self.locate(addr, data.len()) {
            Some((i, off)) => {
                let mut segs = self.segments.write().unwrap();
                segs[i].1[off..off + data.len()].copy_from_slice(data);
                Ok(())
            }
            None => Err(MemError::Write { addr, size: data.len(), reason: "not mapped".into() }),
        }
    }

    fn query(&self, addr: u64) -> Option<Region> {
        self.regions().ok()?.into_iter().find(|r| r.contains(addr))
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let segs = self.segments.read().unwrap();
        Ok(segs
            .iter()
            .map(|(b, d)| Region {
                base: *b,
                size: d.len() as u64,
                allocation_base: *b,
                state: RegionState::Commit,
                protect: Protection { read: true, write: true, raw: 4, ..Default::default() },
                kind: RegionKind::Private,
            })
            .collect())
    }

    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.clone())
    }
}
