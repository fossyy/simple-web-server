package main

import (
	"fmt"
	_ "github.com/fossyy/filekeeper/db"
	indexHandler "github.com/fossyy/filekeeper/handler/index"
	logoutHandler "github.com/fossyy/filekeeper/handler/logout"
	signinHandler "github.com/fossyy/filekeeper/handler/signin"
	signupHandler "github.com/fossyy/filekeeper/handler/signup"
	userHandler "github.com/fossyy/filekeeper/handler/user"
	"github.com/fossyy/filekeeper/middleware"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	serverAddr := "localhost:8000"
	handler := mux.NewRouter()
	server := http.Server{
		Addr:    serverAddr,
		Handler: middleware.Handler(handler),
	}
	handler.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		middleware.Auth(indexHandler.GET, writer, request)
	})

	handler.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			middleware.Guest(signinHandler.GET, w, r)
		case http.MethodPost:
			middleware.Guest(signinHandler.POST, w, r)
		}
	})

	handler.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			middleware.Guest(signupHandler.GET, w, r)
		case http.MethodPost:
			middleware.Guest(signupHandler.POST, w, r)
		}
	})

	handler.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			middleware.Auth(userHandler.GET, w, r)
		}
	})
	handler.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		middleware.Auth(logoutHandler.GET, w, r)
	})

	fileServer := http.FileServer(http.Dir("./public"))
	handler.PathPrefix("/public/").Handler(http.StripPrefix("/public/", fileServer))

	fmt.Printf("Listening on http://%s\n", serverAddr)
	err := server.ListenAndServe()
	if err != nil {
		return
	}

}
