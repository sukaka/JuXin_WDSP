package main

import (
	"fmt"
	"os"
	"github.com/jiuzhang-waf/server/internal/security"
)

func main() {
	err := security.VerifyPassword(os.Args[1], os.Args[2])
	fmt.Println("verify result:", err)
}
