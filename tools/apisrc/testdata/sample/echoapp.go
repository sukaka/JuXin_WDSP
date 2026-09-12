// 样例：echo 风格路由（全大写方法名，:id / * 参数形态）。
package sample

func registerEcho(e echoInstance) {
	e.GET("/echo/users/:id", nil) // :id → {id}
	e.POST("/echo/users", nil)    //
	e.PUT("/dup/:id", nil)        // 与 chiapp.go Put /dup/{id} 去重
	e.GET("/echo/files/*", nil)   // 无名通配 → {wildcard}
	e.HEAD("/echo/head", nil)     //
}
