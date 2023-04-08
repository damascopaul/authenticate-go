package types

type ResponseError struct {
	Message     string       `json:"message"`
	FieldErrors []FieldError `json:"fieldErrors"`
}
