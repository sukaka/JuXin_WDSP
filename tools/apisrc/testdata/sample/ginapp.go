// 样例：gin 风格路由（全大写方法名，:id / *path 参数形态，Handle(method, path)）。
package sample

func registerGin(r ginEngine) {
	r.GET("/gin/users/:id", nil)     // :id → {id}
	r.POST("/gin/users", nil)        //
	r.PATCH("/gin/files/*path", nil) // 具名通配 → {path}
	r.Handle("TRACE", "/gin/raw")    // gin Handle(method, path) 两参形态
	r.OPTIONS("/gin/cors", nil)      //
	r.GET("/gin/dup", nil)           // 与同文件下一行去重（重复注册）
	r.GET("/gin/dup", nil)           // 同行号不同 → sources 两条
}
