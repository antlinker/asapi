# Authorize Server API

> 授权服务的API处理

* 统一的令牌验证
* 提供授权服务所需要的登录验证、增加授权用户信息、更新授权用户信息、删除授权用户信息、修改密码操作
* 提供注册更新授权用户信息的回调处理（用于同步更新用户的验证信息）

## 获取

``` bash
$ go get -u -v github.com/antlinker/asapi
```

## 使用

``` go
package main

import (
	"github.com/antlinker/asapi"
)

func main() {
	// 初始化认证API
	asapi.InitAPI(&asapi.Config{
		ASURL:           "http://127.0.0.1:8099",
		ClientID:        "57a999b57a03b59ebb9b11b0",
		ClientSecret:    "9389211575bfa749b3efdfc3bcd2114e3344e025",
		ServiceIdentify: "TEST",
	})

	// 注册更新用户信息
	// asapi.RegisterUpdateUser()

	// 登录验证
	info, result := asapi.VerifyLogin("username", "password")
	if result != nil {
		// 错误处理
	}

	// 增加用户
	// asapi.AddUser

	// 编辑用户信息
	// asapi.EditUser

	// 删除用户
	// asapi.DelUser

	// 修改密码
	// asapi.ModifyPwd

	// 检查默认密码
	// CheckDefaultPwd

	// 获取令牌
	// GetToken

	// 验证令牌
	// VerifyToken

	// 获取升级令牌
	// GetUpgradeToken
}
```
