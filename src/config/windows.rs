//! Checks Windows file ACLs for access granted to ordinary users.

use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};

use ::windows::Win32::{
    Foundation::{HLOCAL, LocalFree, NO_ERROR, WIN32_ERROR},
    Security::{
        ACL,
        Authorization::{
            BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, TRUSTEE_W,
        },
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_MAX_SID_SIZE, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
    },
    Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    },
};
use ::windows::core::PCWSTR;

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer is allocated by a Windows security API using LocalAlloc.
        unsafe {
            LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

pub(super) fn world_accessible(path: &Path) -> io::Result<bool> {
    // Resolve symlinks and accept relative paths, as the Unix implementation does.
    let path = std::fs::canonicalize(path)?;
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut acl = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and all requested output pointers are valid.
    let code = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            &mut descriptor,
        )
    };
    if code != NO_ERROR {
        return Err(io::Error::from_raw_os_error(code.0 as i32));
    }
    let _descriptor = SecurityDescriptor(descriptor);
    // SAFETY: acl belongs to descriptor, which stays alive throughout the check.
    unsafe { acl_allows_users(acl) }
}

/// The caller must keep the security descriptor owning `acl` alive.
unsafe fn acl_allows_users(acl: *const ACL) -> io::Result<bool> {
    // A null DACL grants everyone full access; an empty DACL grants none.
    if acl.is_null() {
        return Ok(true);
    }
    for kind in [WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid] {
        // u32 storage gives the SID its required alignment.
        let mut sid = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
        let mut size = std::mem::size_of_val(&sid) as u32;
        let mut trustee = TRUSTEE_W::default();
        let mut rights = 0;
        // SAFETY: SID buffer is aligned and large enough, and trustee only borrows it here.
        unsafe {
            let sid = PSID(sid.as_mut_ptr().cast());
            CreateWellKnownSid(kind, None, Some(sid), &mut size).map_err(|error| {
                if let Some(code) = WIN32_ERROR::from_error(&error) {
                    io::Error::from_raw_os_error(code.0 as i32)
                } else {
                    io::Error::other(error)
                }
            })?;
            BuildTrusteeWithSidW(&mut trustee, Some(sid));
            let code = GetEffectiveRightsFromAclW(acl, &trustee, &mut rights);
            if code != NO_ERROR {
                return Err(io::Error::from_raw_os_error(code.0 as i32));
            }
        }
        if rights
            & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER).0
            != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::windows::Win32::Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityDescriptorDacl,
    };
    use ::windows::core::BOOL;

    fn accessible(sddl: &str) -> bool {
        let sddl: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut acl = ptr::null_mut();
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        // SAFETY: each output is valid; the descriptor is freed only after checking its ACL.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                None,
            )
            .unwrap();
            let _descriptor = SecurityDescriptor(descriptor);
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted).unwrap();
            acl_allows_users(acl).unwrap()
        }
    }

    #[test]
    fn broad_file_access_is_detected_with_windows_acls() {
        assert!(accessible("D:(A;;FR;;;WD)"));
        assert!(accessible("D:(A;;FW;;;AU)"));
        assert!(accessible("D:(A;;FR;;;BU)"));
        assert!(!accessible("D:(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert!(!accessible("D:"));
        // SAFETY: null is the documented representation of a null DACL.
        assert!(unsafe { acl_allows_users(ptr::null()) }.unwrap());
    }
}
