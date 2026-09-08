// 样例：chi 风格路由（首字母大写方法名，{id} / {id:regex} 参数形态）。
package sample

func registerChi(r chiRouter) {
	r.Get("/chi/users/{id}", nil)           // {id} 原样保留
	r.Post("/chi/users", nil)               //
	r.Delete("/chi/users/{id:[0-9]+}", nil) // 正则约束 → {id}
	r.Put("/dup/{id}", nil)                 // 与 echoapp.go PUT /dup/:id 去重
	r.Method("CUSTOM", "/chi/custom", nil)  // 非方法名识别集合 → 跳过
}
