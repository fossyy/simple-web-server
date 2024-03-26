package handler

import (
	"net/http"
)

type User struct{}

func (u User) HandleUserShow(w http.ResponseWriter) error {
	return nil
}
