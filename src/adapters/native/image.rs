//! Reviewed Mach-O profile: native slices, closed loader paths, exact signed code.
use crate::access::ports::ExecutionError;
use core_foundation::{
    base::{CFType, TCFType},
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
    url::CFURL,
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use std::path::Path;

fn invalid<T>(_: T) -> ExecutionError {
    ExecutionError::UnsupportedImage
}
fn word(bytes: &[u8], at: usize) -> Result<u32, ExecutionError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(ExecutionError::UnsupportedImage)?
            .try_into()
            .map_err(invalid)?,
    ))
}
fn big(bytes: &[u8], at: usize) -> Result<u32, ExecutionError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(ExecutionError::UnsupportedImage)?
            .try_into()
            .map_err(invalid)?,
    ))
}
fn big64(bytes: &[u8], at: usize) -> Result<usize, ExecutionError> {
    usize::try_from(u64::from_be_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(ExecutionError::UnsupportedImage)?
            .try_into()
            .map_err(invalid)?,
    ))
    .map_err(invalid)
}

pub(crate) fn macho(bytes: &[u8]) -> Result<Vec<usize>, ExecutionError> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(ExecutionError::UnsupportedImage);
    }
    if word(bytes, 0)? == 0xfeedfacf {
        slice(bytes)?;
        return Ok(vec![0]);
    }
    let fat = big(bytes, 0)?;
    if !matches!(fat, 0xcafebabe | 0xcafebabf) {
        return Err(ExecutionError::UnsupportedImage);
    }
    let count = big(bytes, 4)? as usize;
    if count == 0 || count > 16 {
        return Err(ExecutionError::UnsupportedImage);
    }
    let stride = if fat == 0xcafebabf { 32 } else { 20 };
    let mut arm = Vec::new();
    let mut ranges = Vec::new();
    for i in 0..count {
        let p = 8 + i * stride;
        let (offset, size) = if stride == 32 {
            (big64(bytes, p + 8)?, big64(bytes, p + 16)?)
        } else {
            (big(bytes, p + 8)? as usize, big(bytes, p + 12)? as usize)
        };
        let end = offset
            .checked_add(size)
            .ok_or(ExecutionError::UnsupportedImage)?;
        let alignment = big(bytes, p + if stride == 32 { 24 } else { 16 })?;
        if size == 0
            || alignment >= usize::BITS
            || offset % (1usize << alignment) != 0
            || (stride == 32 && big(bytes, p + 28)? != 0)
            || offset < 8 + count * stride
            || end > bytes.len()
            || ranges.iter().any(|&(a, b)| offset < b && end > a)
        {
            return Err(ExecutionError::UnsupportedImage);
        }
        ranges.push((offset, end));
        if big(bytes, p)? == 0x0100000c {
            let native = &bytes[offset..end];
            slice(native)?;
            if word(native, 8)? != big(bytes, p + 4)? {
                return Err(ExecutionError::UnsupportedImage);
            }
            arm.push(offset);
        }
    }
    if arm.is_empty() {
        return Err(ExecutionError::UnsupportedImage);
    }
    Ok(arm)
}
fn slice(bytes: &[u8]) -> Result<(), ExecutionError> {
    if word(bytes, 0)? != 0xfeedfacf || word(bytes, 4)? != 0x0100000c || word(bytes, 12)? != 2 {
        return Err(ExecutionError::UnsupportedImage);
    }
    let count = word(bytes, 16)? as usize;
    let end = 32usize
        .checked_add(word(bytes, 20)? as usize)
        .ok_or(ExecutionError::UnsupportedImage)?;
    if count == 0 || count > 4096 || end > bytes.len() {
        return Err(ExecutionError::UnsupportedImage);
    }
    let mut p = 32;
    let mut signed = false;
    let mut loader = false;
    for _ in 0..count {
        let cmd = word(bytes, p)?;
        let size = word(bytes, p + 4)? as usize;
        if size < 8 || !size.is_multiple_of(8) || p.checked_add(size).is_none_or(|n| n > end) {
            return Err(ExecutionError::UnsupportedImage);
        }
        match cmd {
            0xc | 0x80000018 | 0x8000001f | 0x80000023 => {
                let offset = word(bytes, p + 8)? as usize;
                if offset < 24 || offset >= size {
                    return Err(ExecutionError::UnsupportedImage);
                }
                let value = &bytes[p + offset..p + size];
                let n = value
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or(ExecutionError::UnsupportedImage)?;
                let name = std::str::from_utf8(&value[..n]).map_err(invalid)?;
                if !(name.starts_with("/usr/lib/")
                    || name.starts_with("/System/Library/Frameworks/"))
                    || name.split('/').any(|part| matches!(part, "." | ".."))
                {
                    return Err(ExecutionError::UnsupportedImage);
                }
                // Require the dependency to reside in the OS-signed dyld shared cache.
                let name = std::ffi::CString::new(name).map_err(invalid)?;
                if !unsafe { _dyld_shared_cache_contains_path(name.as_ptr()) } {
                    return Err(ExecutionError::UnsupportedImage);
                }
            }
            0xe => {
                let offset = word(bytes, p + 8)? as usize;
                if loader || offset < 12 || offset >= size {
                    return Err(ExecutionError::UnsupportedImage);
                }
                let value = &bytes[p + offset..p + size];
                let terminator = value
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(ExecutionError::UnsupportedImage)?;
                if &value[..terminator] != b"/usr/lib/dyld" {
                    return Err(ExecutionError::UnsupportedImage);
                }
                loader = true;
            }
            0x1d => {
                if signed
                    || size != 16
                    || word(bytes, p + 12)? == 0
                    || (word(bytes, p + 8)? as usize) < end
                    || (word(bytes, p + 8)? as usize)
                        .checked_add(word(bytes, p + 12)? as usize)
                        .is_none_or(|signature_end| signature_end > bytes.len())
                {
                    return Err(ExecutionError::UnsupportedImage);
                }
                signed = true;
            }
            // Deny rpath, dyld environment, prebound/lazy libraries and alternate loaders.
            0x8000001c | 0x27 | 0x10 | 0x20 | 0xf => return Err(ExecutionError::UnsupportedImage),
            // Recognized metadata/segments only. Unknown future loader behavior fails closed.
            0x19 | 0x2 | 0xb | 0x1b | 0x24 | 0x25 | 0x26 | 0x29 | 0x2a | 0x2b | 0x2d | 0x2e
            | 0x32 | 0x80000022 | 0x80000028 | 0x80000033 | 0x80000034 => {}
            _ => return Err(ExecutionError::UnsupportedImage),
        }
        p += size;
    }
    if p != end || !signed || !loader {
        return Err(ExecutionError::UnsupportedImage);
    }
    Ok(())
}
unsafe extern "C" {
    fn _dyld_shared_cache_contains_path(path: *const libc::c_char) -> bool;
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: *const libc::c_void,
        flags: u32,
        information: *mut core_foundation::dictionary::CFDictionaryRef,
    ) -> i32;
    fn SecStaticCodeCreateWithPathAndAttributes(
        path: core_foundation::url::CFURLRef,
        flags: u32,
        attributes: core_foundation::dictionary::CFDictionaryRef,
        code: *mut *mut libc::c_void,
    ) -> i32;
    static kSecCodeAttributeUniversalFileOffset: core_foundation::string::CFStringRef;
    static kSecCodeInfoUnique: core_foundation::string::CFStringRef;
    static kSecCodeInfoFlags: core_foundation::string::CFStringRef;
    static kSecCodeInfoEntitlementsDict: core_foundation::string::CFStringRef;
}
/// Pin every validated native slice's exact cdhash. Darwin may select arm64e.x1
/// at spawn even when Security's default static object selects arm64e.
pub(crate) fn signature(path: &Path) -> Result<String, ExecutionError> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(invalid)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    let offsets = macho(&bytes)?;
    let url = CFURL::from_path(path, false).ok_or(ExecutionError::UnsafePath)?;
    let mut requirements = std::collections::BTreeSet::new();
    for offset in offsets {
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeAttributeUniversalFileOffset) };
        let number = CFNumber::from(offset as i64);
        let attributes = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), number.as_CFType())]);
        let mut raw = std::ptr::null_mut();
        if unsafe {
            SecStaticCodeCreateWithPathAndAttributes(
                url.as_concrete_TypeRef(),
                0,
                attributes.as_concrete_TypeRef(),
                &mut raw,
            )
        } != 0
            || raw.is_null()
        {
            return Err(ExecutionError::UnsupportedImage);
        }
        let code = unsafe { SecStaticCode::wrap_under_create_rule(raw.cast()) };
        requirements.insert(slice_signature(&code)?);
    }
    Ok(format!(
        "({})",
        requirements.into_iter().collect::<Vec<_>>().join(" or ")
    ))
}
fn slice_signature(code: &SecStaticCode) -> Result<String, ExecutionError> {
    let trusted: SecRequirement="anchor apple or (anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists)".parse().map_err(invalid)?;
    code.check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &trusted)
        .map_err(invalid)?;
    signature_policy(code)
}

// Independently testable policy; production calls it only after strict trusted-chain validation.
fn signature_policy(code: &SecStaticCode) -> Result<String, ExecutionError> {
    let mut info = std::ptr::null();
    if unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 2, &mut info) } != 0
        || info.is_null()
    {
        return Err(ExecutionError::UnsupportedImage);
    }
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };
    let flags = info
        .find(&key)
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|v| v.to_i64())
        .ok_or(ExecutionError::UnsupportedImage)?;
    if flags & 0x10000 == 0 || flags & 0x4 != 0 {
        return Err(ExecutionError::UnsupportedImage);
    }
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoEntitlementsDict) };
    if let Some(value) = info.find(&key) {
        let entitlements = value
            .downcast::<CFDictionary>()
            .ok_or(ExecutionError::UnsupportedImage)?;
        for forbidden in [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.disable-executable-page-protection",
        ] {
            if entitlements.contains_key(&CFString::new(forbidden).as_CFTypeRef()) {
                return Err(ExecutionError::UnsupportedImage);
            }
        }
    }
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
    let hash = info
        .find(&key)
        .and_then(|v| v.downcast::<CFData>())
        .ok_or(ExecutionError::UnsupportedImage)?;
    if hash.len() != 20 {
        return Err(ExecutionError::UnsupportedImage);
    }
    Ok(format!(
        "cdhash H\"{}\"",
        hash.bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

pub(crate) fn dynamic(token: &[u32; 8], requirement: &str) -> Result<(), ExecutionError> {
    let bytes = token
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect::<Vec<_>>();
    let data = CFData::from_buffer(&bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(data.as_concrete_TypeRef());
    let code =
        SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE).map_err(invalid)?;
    let requirement: SecRequirement = requirement.parse().map_err(invalid)?;
    code.check_validity(Flags::STRICT_VALIDATE, &requirement)
        .map_err(invalid)
}

/// Synthetic unit fixtures only: this does not grant production image preparation.
#[cfg(test)]
pub(crate) fn test_requirement(path: &Path) -> Result<String, ExecutionError> {
    let url = CFURL::from_path(path, false).ok_or(ExecutionError::UnsafePath)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(invalid)?;
    let mut info = std::ptr::null();
    if unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 2, &mut info) } != 0
        || info.is_null()
    {
        return Err(ExecutionError::UnsupportedImage);
    }
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
    let hash = info
        .find(&key)
        .and_then(|v| v.downcast::<CFData>())
        .ok_or(ExecutionError::UnsupportedImage)?;
    Ok(format!(
        "cdhash H\"{}\"",
        hash.bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
mod tests;
