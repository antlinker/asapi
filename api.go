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

// RegisterUpdateUser 注册更新用户信息处理
func RegisterUpdateUser(w http.ResponseWriter, r *http.Request, callback func(uid string, info map[string]interface{})) (err error) {
	identify, uid, ok := r.BasicAuth()
	if !ok || identify != gAuthorize.GetConfig().ServiceIdentify {
		err = fmt.Errorf("未识别的用户信息")
		return
	}
	var result map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&result)
	if err != nil {
		return
	}
	callback(uid, result)
	w.Write([]byte("ok"))
	return
}

// VerifyLogin 验证登录
func VerifyLogin(username, password string) (uid string, result *ErrorResult) {
	uid, result = gAuthorize.VerifyLogin(username, password)
	return
}

// AddUser 增加用户
func AddUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
	result = gAuthorize.AddUser(uid, user)
	return
}

// EditUser 编辑用户信息
func EditUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
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
