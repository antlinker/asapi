package asapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/antlinker/go-cache"
	"github.com/astaxie/beego/httplib"
)

// NewAuthorizeHandle 创建授权处理
func NewAuthorizeHandle(cfg *Config) *AuthorizeHandle {
	ah := &AuthorizeHandle{
		cfg: cfg,
		th:  NewTokenHandle(cfg),
	}

	if ah.cfg.IsEnabledCache {
		if ah.cfg.CacheGCInterval == 0 {
			ah.cfg.CacheGCInterval = 300
		}
		ah.cache = cache.New(0, time.Second*time.Duration(ah.cfg.CacheGCInterval))
	}

	return ah
}

// AuthorizeHandle 授权处理
type AuthorizeHandle struct {
	cfg   *Config
	th    *TokenHandle
	cache *cache.Cache
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
	ServiceIdentify string
}

// AddUser 增加用户
func (ah *AuthorizeHandle) AddUser(uid string, user *AuthorizeAddUserRequest) (result *ErrorResult) {
	identify := ah.cfg.ServiceIdentify

	if v := user.ServiceIdentify; v != "" {
		identify = v
	}

	body := map[string]interface{}{
		"ServiceIdentify": identify,
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

// ForceGetToken 强制获取访问令牌
func (ah *AuthorizeHandle) ForceGetToken() (tokenString string, result *ErrorResult) {
	token, result := ah.th.ForceGet()
	if result != nil {
		return
	}
	tokenString = token.AccessToken
	return
}

// VerifyToken 验证令牌
func (ah *AuthorizeHandle) VerifyToken(token string) (userID, clientID string, result *ErrorResult) {
	const (
		userIDKey   = "UserID"
		clientIDKey = "ClientID"
	)

	if ah.cfg.IsEnabledCache {
		// 检查缓存数据
		if at, ok := ah.cache.Get(token); ok {
			if atm, ok := at.(map[string]string); ok {
				userID = atm[userIDKey]
				clientID = atm[clientIDKey]
				return
			}
		}
	}

	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		req = req.Param("access_token", token)
		req = req.Param("service", ah.GetConfig().ServiceIdentify)
		return req, nil
	}

	var resData struct {
		UserID    string `json:"user_id"`
		ClientID  string `json:"client_id"`
		ExpiresIn int    `json:"expires_in"`
	}

	result = ah.request("/oauth2/verify", http.MethodGet, reqHandle, &resData)
	if result != nil {
		return
	}

	userID = resData.UserID
	clientID = resData.ClientID

	if ah.cfg.IsEnabledCache && ah.cfg.CacheGCInterval < resData.ExpiresIn {
		data := map[string]string{
			userIDKey:   resData.UserID,
			clientIDKey: resData.ClientID,
		}
		ah.cache.Set(token, data, time.Duration(resData.ExpiresIn-ah.cfg.CacheGCInterval)*time.Second)
	}

	return
}

// GetUpgradeToken 获取升级令牌
func (ah *AuthorizeHandle) GetUpgradeToken(password, uid, clientID, clientSecret string) (info map[string]interface{}, result *ErrorResult) {

	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		req = req.SetBasicAuth(clientID, clientSecret)

		req = req.Param("grant_type", "password")
		userInfo := map[string]interface{}{
			"LoginModel":   9,
			"UserName":     uid,
			"ClientID":     ah.GetConfig().ClientID,
			"ClientSecret": ah.GetConfig().ClientSecret,
		}

		buf, _ := json.Marshal(userInfo)
		userName := base64.StdEncoding.EncodeToString(buf)
		req = req.Param("username", userName)
		req = req.Param("password", password)

		return req, nil
	}

	result = ah.request("/oauth2/token", http.MethodPost, reqHandle, &info)

	return
}

// UserTokenInfo 用户令牌信息
type UserTokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Expires      int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	UserID       string `json:"user_id"`
}

// UserLoginToken 用户登录令牌
func (ah *AuthorizeHandle) UserLoginToken(userName, password, service string) (tokenInfo *UserTokenInfo, result *ErrorResult) {

	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		req = req.SetBasicAuth(ah.GetConfig().ClientID, ah.GetConfig().ClientSecret)
		req = req.Param("grant_type", "password")

		var userInfo = struct {
			LoginModel int
			UserName   string
			Service    string
		}{
			LoginModel: 1,
			UserName:   userName,
			Service:    service,
		}
		buf, _ := json.Marshal(userInfo)

		userName := base64.StdEncoding.EncodeToString(buf)
		req = req.Param("username", userName)
		req = req.Param("password", password)

		return req, nil
	}

	var info UserTokenInfo
	result = ah.request("/oauth2/token", http.MethodPost, reqHandle, &info)
	if result != nil {
		return
	}
	tokenInfo = &info

	return
}

// UserRefreshToken 用户更新令牌
func (ah *AuthorizeHandle) UserRefreshToken(rtoken string) (tokenInfo *UserTokenInfo, result *ErrorResult) {

	reqHandle := func(req *httplib.BeegoHTTPRequest) (*httplib.BeegoHTTPRequest, *ErrorResult) {
		req = req.SetBasicAuth(ah.GetConfig().ClientID, ah.GetConfig().ClientSecret)
		req = req.Param("grant_type", "refresh_token")
		req = req.Param("refresh_token", rtoken)

		return req, nil
	}

	var info UserTokenInfo
	result = ah.request("/oauth2/token", http.MethodPost, reqHandle, &info)
	if result != nil {
		return
	}
	tokenInfo = &info

	return
}

// AuthorizeMergeUserRequest 合并用户请求参数
type AuthorizeMergeUserRequest struct {
	UID         string
	TUID        string
	TUserCode   string
	TUniversity string
}

// MergeUser 合并用户
func (ah *AuthorizeHandle) MergeUser(req *AuthorizeMergeUserRequest) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"UID":             req.UID,
		"TUID":            req.TUID,
		"TUserCode":       req.TUserCode,
		"TUniversity":     req.TUniversity,
	}

	result = ah.tokenPost("/api/authorize/mergeuser", body, nil)
	return
}

// GetStaffParam 获取学工请求参数
func (ah *AuthorizeHandle) GetStaffParam(identify, uid string) (buID, addr string, result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": identify,
		"UID":             uid,
	}

	var resData struct {
		BuID string
		Addr string
	}

	result = ah.tokenPost("/api/authorize/getstaffparam", body, &resData)
	if result != nil {
		return
	}

	buID = resData.BuID
	addr = resData.Addr

	return
}

// AuthorizeMergeTELUserRequest 合并手机号用户请求参数
type AuthorizeMergeTELUserRequest struct {
	MUID string
	CUID string
}

// MergeTELUser 合并手机号用户
func (ah *AuthorizeHandle) MergeTELUser(req *AuthorizeMergeTELUserRequest) (result *ErrorResult) {
	body := map[string]interface{}{
		"ServiceIdentify": ah.cfg.ServiceIdentify,
		"MUID":            req.MUID,
		"CUID":            req.CUID,
	}

	result = ah.tokenPost("/api/authorize/mergeteluser", body, nil)
	return
}
