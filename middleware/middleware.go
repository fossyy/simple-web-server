package middleware

import (
	"fmt"
	"github.com/fossyy/filekeeper/utils"
	"net/http"
)

func Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(writer, request)
		fmt.Printf("%s %s %s \n", utils.ClientIP(request), request.Method, request.RequestURI)
	})
}
