package types

type Message struct {
	Code    int
	Message string
}

type User struct {
	Email         string
	Username      string
	Authenticated bool
}
