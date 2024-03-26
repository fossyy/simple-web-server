package main

import (
	"encoding/gob"
	"fmt"
	"github.com/fossyy/filekeeper/db"
	_ "github.com/fossyy/filekeeper/db"
	"github.com/fossyy/filekeeper/middleware"
	"github.com/fossyy/filekeeper/types"
	signin "github.com/fossyy/filekeeper/view/signin"
	"github.com/fossyy/filekeeper/view/signup"
	user "github.com/fossyy/filekeeper/view/user"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type User struct {
	Email         string
	Username      string
	Authenticated bool
}

var store *sessions.CookieStore

func init() {
	authKeyOne := securecookie.GenerateRandomKey(64)
	encryptionKeyOne := securecookie.GenerateRandomKey(32)

	store = sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)

	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
	}

	gob.Register(User{})
}

func main() {
	serverAddr := "192.168.1.3:8000"
	handler := mux.NewRouter()
	server := http.Server{
		Addr:    serverAddr,
		Handler: middleware.Handler(handler),
	}
	handler.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		userSession := getUser(session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if userSession.Authenticated {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
			return
		}
		switch r.Method {
		case http.MethodGet:
			component := signin.Main("Sign in Page", types.Message{
				Code:    3,
				Message: "",
			})
			component.Render(r.Context(), w)
		case http.MethodPost:
			err = r.ParseForm()
			if err != nil {
				http.Error(w, "Error parsing form", http.StatusBadRequest)
				return
			}
			email := r.Form.Get("email")
			password := r.Form.Get("password")
			var userData db.User

			if err := db.DB.Table("users").Where("email = ?", email).First(&userData).Error; err != nil {
				component := signin.Main("Sign in Page", types.Message{
					Code:    0,
					Message: "Database error : " + err.Error(),
				})
				component.Render(r.Context(), w)
			}
			if email == userData.Email && CheckPasswordHash(password, userData.Password) {
				session.Values["user"] = User{
					Email:         email,
					Username:      userData.Username,
					Authenticated: true,
				}
				err = session.Save(r, w)
				http.Redirect(w, r, "/user", http.StatusSeeOther)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				return
			}
			component := signin.Main("Sign in Page", types.Message{
				Code:    0,
				Message: "User atau password salah",
			})
			component.Render(r.Context(), w)
		}

	})

	handler.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		userSession := getUser(session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if userSession.Authenticated {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
			return
		}
		switch r.Method {
		case http.MethodGet:
			component := signup.Main("Sign up Page", types.Message{
				Code:    3,
				Message: "",
			})
			component.Render(r.Context(), w)
		case http.MethodPost:
			err = r.ParseForm()
			if err != nil {
				http.Error(w, "Error parsing form", http.StatusBadRequest)
				return
			}
			email := r.Form.Get("email")
			username := r.Form.Get("username")
			password := r.Form.Get("password")
			hashedPassword, err := HashPassword(password)

			newUser := db.User{
				Username: username,
				Email:    email,
				Password: hashedPassword,
			}

			err = db.DB.Create(&newUser).Error

			if err != nil {
				component := signup.Main("Sign up Page", types.Message{
					Code:    0,
					Message: "Username atau Email sudah terdaftar",
				})
				component.Render(r.Context(), w)
				return
			}

			component := signup.Main("Sign up Page", types.Message{
				Code:    1,
				Message: "User creation success",
			})
			component.Render(r.Context(), w)
		}

	})

	handler.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		userSession := getUser(session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		switch r.Method {
		case http.MethodGet:

			if !userSession.Authenticated {
				http.Redirect(w, r, "/signin", http.StatusSeeOther)
				return
			}
			component := user.Main("anjay mabar", userSession.Email, userSession.Username)
			component.Render(r.Context(), w)
		}

	})
	handler.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		switch r.Method {
		case http.MethodGet:
			session.Options.MaxAge = -1
			session.Values["user"] = User{}
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
		}
	})
	fileServer := http.FileServer(http.Dir("./public"))

	handler.PathPrefix("/public/").Handler(http.StripPrefix("/public/", fileServer))

	fmt.Printf("Listening on http://%s\n", serverAddr)
	err := server.ListenAndServe()
	if err != nil {
		return
	}

}

func getUser(s *sessions.Session) User {
	val := s.Values["user"]
	var userSession = User{}
	userSession, ok := val.(User)
	if !ok {
		return User{Authenticated: false}
	}
	return userSession
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
