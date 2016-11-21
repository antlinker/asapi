package asapi

import (
	"bytes"
	"errors"
)

// Config 配置参数
type Config struct {
	ASURL           string // 授权服务URL
	ClientID        string // 客户端ID
	ClientSecret    string // 客户端秘钥
	ServiceIdentify string // 服务标识
}

// GetURL 获取请求的URL
func (c *Config) GetURL(router string) string {
	var buf bytes.Buffer
	if l := len(c.ASURL); c.ASURL[l-1] == '/' {
		c.ASURL = c.ASURL[:l-1]
	}
	buf.WriteString(c.ASURL)
	if l := len(router); l > 0 && router[0] != '/' {
		buf.WriteByte('/')
	}
	buf.WriteString(router)
	return buf.String()
}

// ErrorResult 响应错误结果
type ErrorResult struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error 实现error接口
func (er *ErrorResult) Error() string {
	return er.Message
}

// NewErrorResult 创建错误结果
func NewErrorResult(msg string, code ...int) *ErrorResult {
	result := &ErrorResult{
		Message: msg,
	}
	if len(code) > 0 {
		result.Code = code[0]
	}
	return result
}
