package asapi

import (
	"testing"
)

func TestGetUser(t *testing.T) {
	ah := NewAuthorizeHandle(gconfig)
	info, ar := ah.GetUser("e086de96-0e24-4eaf-a2a2-d8336cc2d686")
	t.Log(info, ar)
}
