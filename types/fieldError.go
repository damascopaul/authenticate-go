package types

type FieldError struct {
	Error string `json:"error"`
	Name  string `json:"name"`
}
