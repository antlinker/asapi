package asapi

import (
	"github.com/astaxie/beego/httplib"
)

// NewAuthorizeHandle 创建授权处理
func NewAuthorizeHandle(cfg *Config) *AuthorizeHandle {
	return &AuthorizeHandle{
		cfg: cfg,
		th:  NewTokenHandle(cfg),
	}
}

// AuthorizeHandle 授权处理
type AuthorizeHandle struct {
	cfg *Config
	th  *TokenHandle
}

func (ah *AuthorizeHandle) request(router string, body, v interface{}) (result *ErrorResult) {
	token, result := ah.th.Get()
	if result != nil {
		return
	}
	req := httplib.Post(ah.cfg.GetURL(router))
	req, err := req.JSONBody(body)
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	}
	req.Header("AccessToken", token)
	res, err := req.Response()
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	} else if res.StatusCode != 200 {
		var resResult ErrorResult
		err = req.ToJSON(&resResult)
		if err != nil {
			result = NewErrorResult(err.Error())
			return
		}
		result = &resResult
		return
	}
	if v == nil {
		return
	}
	err = req.ToJSON(v)
	if err != nil {
		result = NewErrorResult(err.Error())
	}
	return
}

// GetConfig 获取配置参数
func (ah *AuthorizeHandle) GetConfig() (cfg *Config) {
	cfg = ah.cfg
	return
}

// VerifyLogin 验证登录
func (ah *AuthorizeHandle) VerifyLogin(username, password string) (uid string, result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UserName":        username,
		"Password":        password,
	}
	var resResult struct {
		UID string
	}
	result = ah.request("/api/authorize/verifylogin", body, &resResult)
	if result != nil {
		return
	}
	uid = resResult.UID
	return
}

// AuthorizeAddUserRequest 增加用户信息请求
type AuthorizeAddUserRequest struct {
	MobilePhone     string
	UserCode        string
	IDCard          string
	Password        string
	DefaultPassword string
	University      string
}

// AddUser 增加用户
func (ah *AuthorizeHandle) AddUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
		"MobilePhone":     user.MobilePhone,
		"UserCode":        user.UserCode,
		"IDCard":          user.IDCard,
		"Password":        user.Password,
		"DefaultPassword": user.DefaultPassword,
		"University":      user.University,
	}
	result = ah.request("/api/authorize/adduser", body, nil)
	return
}

// AuthorizeEditUserRequest 编辑用户信息请求
type AuthorizeEditUserRequest struct {
	MobilePhone string
	UserCode    string
	IDCard      string
}

// EditUser 编辑用户信息
func (ah *AuthorizeHandle) EditUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
		"MobilePhone":     user.MobilePhone,
		"UserCode":        user.UserCode,
		"IDCard":          user.IDCard,
	}
	result = ah.request("/api/authorize/edituser", body, nil)
	return
}

// DelUser 删除用户
func (ah *AuthorizeHandle) DelUser(uid string) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
	}
	result = ah.request("/api/authorize/deluser", body, nil)
	return
}

// ModifyPwd 修改密码
func (ah *AuthorizeHandle) ModifyPwd(uid, password string) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
		"Password":        password,
	}
	result = ah.request("/api/authorize/modifypwd", body, nil)
	return
}
