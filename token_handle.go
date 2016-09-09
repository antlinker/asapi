package asapi

import (
	"sync"
	"time"

	"github.com/astaxie/beego/httplib"
)

// Token 令牌信息
type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	CreateTime  time.Time `json:"-"`
}

// NewTokenHandle 创建令牌验证
func NewTokenHandle(cfg *Config) *TokenHandle {
	return &TokenHandle{
		cfg: cfg,
	}
}

// TokenHandle 令牌验证处理
type TokenHandle struct {
	cfg   *Config
	lock  sync.Mutex
	token *Token
}

// Get 获取令牌
func (th *TokenHandle) Get() (token string, result *ErrorResult) {
	th.lock.Lock()
	defer th.lock.Unlock()
	if th.token == nil ||
		th.token.CreateTime.Add(time.Duration(th.token.ExpiresIn+10)*time.Second).Before(time.Now()) {
		req := httplib.Post(th.cfg.GetURL("/oauth2/token"))
		req = req.SetBasicAuth(th.cfg.ClientID, th.cfg.ClientSecret)
		req = req.Param("grant_type", "client_credentials")
		res, err := req.Response()
		if err != nil {
			result = NewErrorResult(err.Error())
			return
		} else if res.StatusCode != 200 {
			var resResult struct {
				Error string `json:"error"`
			}
			err = req.ToJSON(&resResult)
			if err != nil {
				result = NewErrorResult(err.Error())
				return
			}
			result = NewErrorResult(resResult.Error)
			return
		}
		var t Token
		err = req.ToJSON(&t)
		if err != nil {
			result = NewErrorResult(err.Error())
			return
		}
		t.CreateTime = time.Now()
		th.token = &t
	}
	token = th.token.AccessToken
	return
}
