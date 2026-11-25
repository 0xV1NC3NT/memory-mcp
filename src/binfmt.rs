//! Executable image formats of loaded modules, detected from the header in memory.
//! Callers (address expressions, scan scopes) use these format-neutral entry points;
//! PE (Windows) is implemented in `pe`, ELF (Linux) is detected and reported as unsupported
//! until the Linux backend adds `elf`.

use crate::error::{MemError, Result};
use crate::pe;
use crate::platform::{Module, ProcessMemory};

pub use crate::pe::{ExportHit, Section};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Pe,
    Elf,
    Unknown,
}

pub fn detect(p: &dyn ProcessMemory, base: u64) -> ImageFormat {
    let mut magic = [0u8; 4];
    if p.read(base, &mut magic).is_err() {
        return ImageFormat::Unknown;
    }
    match magic {
        [b'M', b'Z', ..] => ImageFormat::Pe,
        [0x7F, b'E', b'L', b'F'] => ImageFormat::Elf,
        _ => ImageFormat::Unknown,
    }
}

fn unknown(m: &Module) -> MemError {
    MemError::InvalidArg(format!("module {} has no recognizable executable header (MZ or ELF) at {:#x}", m.name, m.base))
}

/// Address of an exported symbol (`Name` or `#ordinal`), following forwarders where the format has them.
pub fn resolve_export(p: &dyn ProcessMemory, modules: &[Module], module: &Module, symbol: &str) -> Result<ExportHit> {
    match detect(p, module.base) {
        ImageFormat::Pe => pe::resolve_export(p, modules, module, symbol),
        ImageFormat::Elf => Err(MemError::Unsupported("export lookup in ELF modules")),
        ImageFormat::Unknown => Err(unknown(module)),
    }
}

/// All named exports of a module, sorted by address (empty for formats without support).
pub fn exports(p: &dyn ProcessMemory, module: &Module) -> Result<Vec<(u64, String)>> {
    match detect(p, module.base) {
        ImageFormat::Pe => pe::exports(p, module),
        ImageFormat::Elf => Err(MemError::Unsupported("export listing of ELF modules")),
        ImageFormat::Unknown => Ok(Vec::new()),
    }
}

/// Function table with exact boundaries (x64 PE `.pdata`); empty when the format has none.
pub fn runtime_functions(p: &dyn ProcessMemory, module: &Module) -> Result<Vec<pe::RuntimeFunction>> {
    match detect(p, module.base) {
        ImageFormat::Pe if module.arch == Some(crate::platform::Arch::X64) => pe::runtime_functions(p, module.base),
        _ => Ok(Vec::new()),
    }
}

/// Parent of a chained (fragment) entry from [`runtime_functions`].
pub fn chained_parent(p: &dyn ProcessMemory, module: &Module, f: &pe::RuntimeFunction) -> Option<pe::RuntimeFunction> {
    match detect(p, module.base) {
        ImageFormat::Pe => pe::chained_parent(p, module.base, f),
        _ => None,
    }
}

/// Sections of a module image (`.text`, `.rdata`, `.data` …).
pub fn sections(p: &dyn ProcessMemory, module: &Module) -> Result<Vec<Section>> {
    match detect(p, module.base) {
        ImageFormat::Pe => pe::sections(p, module.base),
        ImageFormat::Elf => Err(MemError::Unsupported("section headers of ELF modules")),
        ImageFormat::Unknown => Err(unknown(module)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    #[test]
    fn dispatch_by_header() {
        let mut m = MockProcess::new(Arch::X64);
        m.add_module("a.dll", 0x10000, testpe::image(true, "A.Alpha"));
        let mut elf = vec![0u8; 0x100];
        elf[..4].copy_from_slice(b"\x7FELF");
        m.add_module("libx.so", 0x20000, elf);
        m.add_module("blob", 0x30000, vec![0u8; 0x100]);
        let mods = m.modules().unwrap();
        let get = |n: &str| mods.iter().find(|x| x.name == n).unwrap().clone();

        assert_eq!(detect(&m, 0x10000), ImageFormat::Pe);
        assert_eq!(detect(&m, 0x20000), ImageFormat::Elf);
        assert_eq!(detect(&m, 0x30000), ImageFormat::Unknown);
        assert_eq!(resolve_export(&m, &mods, &get("a.dll"), "Alpha").unwrap().address, 0x11000);
        assert!(matches!(resolve_export(&m, &mods, &get("libx.so"), "x"), Err(MemError::Unsupported(_))));
        assert!(matches!(sections(&m, &get("libx.so")), Err(MemError::Unsupported(_))));
        assert!(sections(&m, &get("blob")).unwrap_err().to_string().contains("no recognizable executable header"));
    }
}
