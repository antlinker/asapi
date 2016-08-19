package asapi

import (
	"testing"
)

func TestTokenHandleGet(t *testing.T) {
	th := NewTokenHandle(gconfig)
	token, result := th.Get()
	if result != nil {
		t.Error(result.Code, result.Message)
		return
	}
	t.Log("Access Token:", token)
}
