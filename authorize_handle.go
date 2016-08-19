package asapi

import (
	"github.com/astaxie/beego/httplib"
)

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
	req, err = req.JSONBody(body)
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	}
	req.Header("AccessToken", token)
	err = req.ToJSON(v)
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	}
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
	UID             string
	MobilePhone     string
	UserCode        string
	IDCard          string
	Password        string
	DefaultPassword string
}

// AddUser 增加用户
func (ah *AuthorizeHandle) AddUser() (result *ErrorResult) {
	return
}
