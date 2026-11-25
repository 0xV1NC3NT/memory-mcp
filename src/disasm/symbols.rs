//! Symbol names for disassembly: module exports (`kernel32.dll!Sleep`) and `module+0xOFF`.

use std::collections::HashMap;
use std::sync::Arc;

use iced_x86::{Instruction, SymbolResolver, SymbolResult};

use crate::binfmt;
use crate::platform::{Module, ProcessMemory};

type ExportList = Arc<Vec<(u64, String)>>;

/// Immutable snapshot used by one formatting pass.
#[derive(Clone, Default)]
pub struct SymbolTable {
    modules: Arc<Vec<Module>>,
    exports: HashMap<u64, ExportList>,
}

impl SymbolTable {
    pub fn module_of(&self, a: u64) -> Option<&Module> {
        let i = self.modules.partition_point(|m| m.base <= a);
        let m = self.modules.get(i.checked_sub(1)?)?;
        m.contains(a).then_some(m)
    }

    /// `module!export` for an exact export address.
    pub fn export_at(&self, a: u64) -> Option<String> {
        let m = self.module_of(a)?;
        let list = self.exports.get(&m.base)?;
        let i = list.partition_point(|(addr, _)| *addr < a);
        let (addr, name) = list.get(i)?;
        (*addr == a).then(|| format!("{}!{name}", m.name))
    }

    /// Export name, else `module+0xOFF`, else None (heap, stack…).
    pub fn name(&self, a: u64) -> Option<String> {
        if let Some(e) = self.export_at(a) {
            return Some(e);
        }
        self.module_of(a).map(|m| format!("{}+0x{:X}", m.name, a - m.base))
    }
}

/// Per-process cache of export lists (modules are re-listed on every use, exports parsed once).
#[derive(Default)]
pub struct SymbolCache {
    pid: u32,
    exports: HashMap<(u64, u64), ExportList>,
}

impl SymbolCache {
    /// Builds a table with exports loaded for every module containing one of `addrs`.
    pub fn table_for(&mut self, p: &dyn ProcessMemory, addrs: &[u64]) -> SymbolTable {
        if self.pid != p.pid() {
            self.pid = p.pid();
            self.exports.clear();
        }
        let mut modules = p.modules().unwrap_or_default();
        modules.sort_by_key(|m| m.base);
        let mut table = SymbolTable { modules: Arc::new(modules), exports: HashMap::new() };
        for &a in addrs {
            let Some(m) = table.module_of(a).cloned() else { continue };
            if table.exports.contains_key(&m.base) {
                continue;
            }
            let list = self
                .exports
                .entry((m.base, m.size))
                .or_insert_with(|| Arc::new(binfmt::exports(p, &m).unwrap_or_default()))
                .clone();
            table.exports.insert(m.base, list);
        }
        table
    }
}

/// iced symbol resolver backed by a [`SymbolTable`] snapshot and optional local labels.
pub struct Resolver {
    pub table: SymbolTable,
    pub labels: Arc<HashMap<u64, String>>,
}

impl SymbolResolver for Resolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        if let Some(l) = self.labels.get(&address) {
            return Some(SymbolResult::with_string(address, l.clone()));
        }
        // Small constants are never symbols.
        if address < 0x10000 {
            return None;
        }
        self.table.name(address).map(|s| SymbolResult::with_string(address, s))
    }
}
