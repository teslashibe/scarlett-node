package worker

import "golang.org/x/sys/windows"

func makeSessionPublic(path string) error { return setSessionACL(path, "D:P(A;;FA;;;WD)") }
func makeSessionPrivate(path string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return setSessionACL(path, "D:P(A;;FA;;;"+u.User.Sid.String()+")(A;;FA;;;SY)")
}
func setSessionACL(path, descriptor string) error {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
