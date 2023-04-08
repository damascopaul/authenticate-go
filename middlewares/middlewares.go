package middlewares

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func InjectRequestIDMiddleware(c *gin.Context) {
	id := uuid.New()
	c.Set("RequestID", id.String())
	c.Next()
}
