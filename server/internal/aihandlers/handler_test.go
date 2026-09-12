// handler_test.go 路由注册冒烟测试：Go ServeMux 模式冲突只会在注册时 panic，此处提前暴露。
package aihandlers

import (
	"net/http"
	"testing"
)

// TestRegisterRoutesNoPanic 注册全部 AI 路由不得出现模式冲突。
func TestRegisterRoutesNoPanic(t *testing.T) {
	mux := http.NewServeMux()
	d := NewDeps(Deps{})
	d.RegisterRoutes(mux, func(h http.Handler) http.Handler { return h })
}
