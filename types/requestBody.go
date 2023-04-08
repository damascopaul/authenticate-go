package types

type RequestBody struct {
	Token string `json:"token" validate:"required,max=2048"`
}
