package asapi

import (
	"encoding/json"
	"net/http"

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

// 请求数据
func (ah *AuthorizeHandle) request(router, method string, reqHandle func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult), v interface{}) (result *ErrorResult) {
	req := httplib.NewBeegoRequest(ah.cfg.GetURL(router), method)

	if reqHandle != nil {
		vreq, vresult := reqHandle(req)
		if vresult != nil {
			result = vresult
			return
		}
		req = vreq
	}

	res, err := req.Response()
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	}

	buf, err := req.Bytes()
	if err != nil {
		result = NewErrorResult(err.Error())
		return
	}

	switch res.StatusCode {
	case 200:
		if v == nil {
			return
		}
		err = json.Unmarshal(buf, v)
		if err != nil {
			result = NewErrorResult(err.Error())
		}
	default:
		result = NewErrorResult(string(buf), res.StatusCode)
	}

	return
}

// 带有访问令牌的post请求
func (ah *AuthorizeHandle) tokenPost(router string, body, v interface{}) (result *ErrorResult) {
	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		token, result := ah.th.Get()
		if result != nil {
			return req, result
		}
		req = req.Header("AccessToken", token)

		if body != nil {
			vreq, err := req.JSONBody(body)
			if err != nil {
				result = NewErrorResult(err.Error())
				return req, result
			}
			req = vreq
		}
		return req, nil
	}
	result = ah.request(router, http.MethodPost, reqHandle, v)
	return
}

// GetConfig 获取配置参数
func (ah *AuthorizeHandle) GetConfig() (cfg *Config) {
	cfg = ah.cfg
	return
}

// LoginUserInfo 登录用户信息
type LoginUserInfo struct {
	MobilePhone     string // 手机号码
	UserCode        string // 用户代码
	IDCard          string // 身份证号码
	Password        string // 登录密码
	DefaultPassword string // 默认登录密码
	University      string // 学校ID
}

// VerifyLogin 验证登录
// username 用户ID（唯一标识）
// password 密码
func (ah *AuthorizeHandle) VerifyLogin(username, password string) (info *LoginUserInfo, result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             username,
		"Password":        password,
	}
	var loginInfo LoginUserInfo
	result = ah.tokenPost("/api/authorize/verifylogin", body, &loginInfo)
	if result != nil {
		return
	}
	info = &loginInfo
	return
}

// GetUser 验证登录
// uid 用户ID（唯一标识）
func (ah *AuthorizeHandle) GetUser(uid string) (info *LoginUserInfo, result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
	}
	var loginInfo LoginUserInfo
	result = ah.tokenPost("/api/authorize/getuser", body, &loginInfo)
	if result != nil {
		return
	}
	info = &loginInfo
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
	result = ah.tokenPost("/api/authorize/adduser", body, nil)
	return
}

// AuthorizeEditUserRequest 编辑用户信息请求
type AuthorizeEditUserRequest struct {
	MobilePhone string
	UserCode    string
	IDCard      string
	University  string
}

// EditUser 编辑用户信息
func (ah *AuthorizeHandle) EditUser(uid string, user *AuthorizeEditUserRequest) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
		"MobilePhone":     user.MobilePhone,
		"UserCode":        user.UserCode,
		"IDCard":          user.IDCard,
		"University":      user.University,
	}
	result = ah.tokenPost("/api/authorize/edituser", body, nil)
	return
}

// DelUser 删除用户
func (ah *AuthorizeHandle) DelUser(uid string) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
	}
	result = ah.tokenPost("/api/authorize/deluser", body, nil)
	return
}

// ModifyPwd 修改密码
func (ah *AuthorizeHandle) ModifyPwd(uid, password string) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
		"Password":        password,
	}
	result = ah.tokenPost("/api/authorize/modifypwd", body, nil)
	return
}

// CheckDefaultPwd 检查默认密码
func (ah *AuthorizeHandle) CheckDefaultPwd(uid string) (isDefault bool, result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             uid,
	}

	var res struct {
		IsDefault bool
	}
	result = ah.tokenPost("/api/authorize/checkdefaultpwd", body, &res)
	if result != nil {
		return
	}
	isDefault = res.IsDefault
	return
}

// GetToken 获取访问令牌
func (ah *AuthorizeHandle) GetToken() (token string, result *ErrorResult) {
	token, result = ah.th.Get()
	return
}

// VerifyToken 验证令牌
func (ah *AuthorizeHandle) VerifyToken(token string) (userID, clientID string, result *ErrorResult) {

	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		req = req.Param("access_token", token)
		return req, nil
	}

	var resData struct {
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
	}

	result = ah.request("/oauth2/verify", http.MethodGet, reqHandle, &resData)
	if result != nil {
		return
	}

	userID = resData.UserID
	clientID = resData.ClientID

	return
}
