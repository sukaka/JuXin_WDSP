//go:build windows

// Package fsperm 跨平台私有目录与凭据文件权限保护。
// Windows 平台通过受保护 NTFS DACL（禁用继承）限制私有目录与 0600 凭据文件
// 仅允许 SYSTEM、BUILTIN\Administrators（及非管理员自测时的当前所有者）访问。
package fsperm

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// MkdirPrivate 创建私有目录并施加受保护 NTFS DACL。
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建私有目录 %s: %w", dir, err)
	}
	if err := applyPrivateDACL(dir, true); err != nil {
		return fmt.Errorf("设置私有目录 NTFS ACL %s: %w", dir, err)
	}
	return nil
}

// SecureFile 设置文件权限：当 perm 禁止 group/other 访问（perm&0o077 == 0，如 0600）
// 时施加受保护 NTFS DACL；公开可读文件（如 0644 证书）保持目录继承权限。
func SecureFile(path string, perm os.FileMode) error {
	if perm&0o077 != 0 {
		return nil
	}
	if err := applyPrivateDACL(path, false); err != nil {
		return fmt.Errorf("设置私有文件 NTFS ACL %s: %w", path, err)
	}
	return nil
}

func applyPrivateDACL(path string, isDir bool) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("构造 SYSTEM SID: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("构造 Administrators SID: %w", err)
	}

	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_ALIAS,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	// 若当前进程在非管理员/非 SYSTEM 账户下运行（如开发/单测用户目录），
	// 追加当前进程用户 SID，防止写入后自锁，同时仍阻断其他本地普通用户读取。
	if userSID, err := currentProcessUserSID(); err == nil && userSID != nil {
		if !userSID.Equals(systemSID) && !userSID.Equals(adminSID) {
			entries = append(entries, windows.EXPLICIT_ACCESS{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       inherit,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_USER,
					TrusteeValue: windows.TrusteeValueFromSID(userSID),
				},
			})
		}
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("构造 DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("应用 DACL: %w", err)
	}
	return nil
}

func currentProcessUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	tu, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}
