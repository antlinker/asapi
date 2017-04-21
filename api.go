package asapi

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	gAuthorize *AuthorizeHandle
)

// InitAPI API初始化
func InitAPI(cfg *Config) {
	gAuthorize = NewAuthorizeHandle(cfg)
}

// UserInfo 更新用户信息
type UserInfo struct {
	MobilePhone string
	UserCode    string
	IDCard      string
}

// RegisterUpdateUser 注册更新用户信息处理
func RegisterUpdateUser(w http.ResponseWriter, r *http.Request, callback func(uid string, info *UserInfo)) (err error) {
	identify, uid, ok := r.BasicAuth()
	if !ok || identify != gAuthorize.GetConfig().ServiceIdentify {
		err = fmt.Errorf("未识别的用户信息")
		return
	}
	var result UserInfo
	err = json.NewDecoder(r.Body).Decode(&result)
	if err != nil {
		return
	}
	callback(uid, &result)
	w.Write([]byte("ok"))
	return
}

// VerifyLogin 验证登录
// username 用户ID（唯一标识）
// password 密码
// 登录错误码说明：11 未知的用户,12 无效的用户,13 无效的密码
func VerifyLogin(username, password string) (info *LoginUserInfo, result *ErrorResult) {
	info, result = gAuthorize.VerifyLogin(username, password)
	return
}

// GetUser 验证登录
// uid 用户ID（唯一标识）
func GetUser(uid string) (info *LoginUserInfo, result *ErrorResult) {
	info, result = gAuthorize.GetUser(uid)
	return
}

// AddUser 增加用户
func AddUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
	result = gAuthorize.AddUser(uid, user)
	return
}

// EditUser 编辑用户信息
func EditUser(uid string, user *AuthorizeEditUserRequest) (result *ErrorResult) {
	result = gAuthorize.EditUser(uid, user)
	return
}

// DelUser 删除用户
func DelUser(uid string) (result *ErrorResult) {
	result = gAuthorize.DelUser(uid)
	return
}

// ModifyPwd 修改密码
func ModifyPwd(uid, password string, services ...string) (result *ErrorResult) {
	result = gAuthorize.ModifyPwd(uid, password, services...)
	return
}

// CheckDefaultPwd 检查默认密码
func CheckDefaultPwd(uid string) (isDefault bool, result *ErrorResult) {
	isDefault, result = gAuthorize.CheckDefaultPwd(uid)
	return
}

// GetToken 获取令牌
func GetToken() (token string, result *ErrorResult) {
	token, result = gAuthorize.GetToken()
	return
}

// ForceGetToken 强制获取访问令牌
func ForceGetToken() (tokenString string, result *ErrorResult) {
	tokenString, result = gAuthorize.ForceGetToken()
	return
}

// VerifyToken 验证令牌
func VerifyToken(token string) (userID, clientID string, result *ErrorResult) {
	userID, clientID, result = gAuthorize.VerifyToken(token)
	return
}

// GetUpgradeToken 获取升级令牌
func GetUpgradeToken(password, uid, clientID, clientSecret string) (info map[string]interface{}, result *ErrorResult) {
	info, result = gAuthorize.GetUpgradeToken(password, uid, clientID, clientSecret)
	return
}

// MergeUser 合并认证用户
func MergeUser(req *AuthorizeMergeUserRequest) (result *ErrorResult) {
	result = gAuthorize.MergeUser(req)
	return
}

// GetStaffParam 获取学工请求参数
func GetStaffParam(identify, uid string) (buID, addr string, result *ErrorResult) {
	buID, addr, result = gAuthorize.GetStaffParam(identify, uid)
	return
}

// UserLoginToken 用户登录令牌
func UserLoginToken(userName, password, service string) (tokenInfo *UserTokenInfo, result *ErrorResult) {
	tokenInfo, result = gAuthorize.UserLoginToken(userName, password, service)
	return
}

// UserRefreshToken 用户更新令牌
func UserRefreshToken(rtoken string) (tokenInfo *UserTokenInfo, result *ErrorResult) {
	tokenInfo, result = gAuthorize.UserRefreshToken(rtoken)
	return
}

// MergeTELUser 合并手机号用户
func MergeTELUser(req *AuthorizeMergeTELUserRequest) (result *ErrorResult) {
	result = gAuthorize.MergeTELUser(req)
	return
}

// ClearAuth 清理用户认证信息
func ClearAuth(req *ClearAuthRequest) (result *ErrorResult) {
	result = gAuthorize.ClearAuth(req)
	return
}

// GetUserCode 根据用户ID获取UserCode
func GetUserCode(uid string) (userCode string, result *ErrorResult) {
	userCode, result = gAuthorize.GetUserCode(uid)
	return
}

// AddStaffUser 增加学工用户
func AddStaffUser(req *AddStaffUserRequest) (result *ErrorResult) {
	result = gAuthorize.AddStaffUser(req)
	return
}

// UpdateUserBasic 更新用户基础信息
func UpdateUserBasic(req *UpdateUserBasicRequest) (result *ErrorResult) {
	result = gAuthorize.UpdateUserBasic(req)
	return
}

// GetUserVersion 获取用户版本信息
func GetUserVersion(uid string) (resResult *GetUserVersionResult, result *ErrorResult) {
	resResult, result = gAuthorize.GetUserVersion(uid)
	return
}

// UserActivate 用户激活
func UserActivate(uid string) (resResult *UserActivateResult, result *ErrorResult) {
	resResult, result = gAuthorize.UserActivate(uid)
	return
}

// GetUserUpdate 获取获取用户更新信息
func GetUserUpdate(uid string) (resResult *GetUserUpdateResult, result *ErrorResult) {
	resResult, result = gAuthorize.GetUserUpdate(uid)
	return
}

// DelStaffUser 删除学工用户
func DelStaffUser(uid string) (result *ErrorResult) {
	result = gAuthorize.DelStaffUser(uid)
	return
}

// UpdateAuthStatus 更新用户认证状态
func UpdateAuthStatus(uid string) (result *ErrorResult) {
	result = gAuthorize.UpdateAuthStatus(uid)
	return
}
