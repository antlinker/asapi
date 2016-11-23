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
func ModifyPwd(uid, password string) (result *ErrorResult) {
	result = gAuthorize.ModifyPwd(uid, password)
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

// VerifyToken 验证令牌
func VerifyToken(token string) (userID, clientID string, result *ErrorResult) {
	userID, clientID, result = gAuthorize.VerifyToken(token)
	return
}

// MergeUser 合并认证用户
func MergeUser(req *AuthorizeMergeUserRequest) (result *ErrorResult) {
	result = gAuthorize.MergeUser(req)
	return
}
