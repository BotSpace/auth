package middlewares

import (
	"net/http"
	"strings"

	"github.com/JscorpTech/auth/internal/config"
	"github.com/JscorpTech/auth/internal/dto"
	"github.com/JscorpTech/auth/pkg/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func AuthMiddleware(cfg *config.Config, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenRaw := c.Request.Header.Get("Authorization")
		parts := strings.SplitN(tokenRaw, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
			dto.JSON(c, http.StatusUnauthorized, nil, "Authorization header must use Bearer token")
			c.Abort()
			return
		}
		token := strings.TrimSpace(parts[1])
		claims, err := utils.VerifyJWT(token, cfg.PublicKey)

		if err != nil {
			dto.JSON(c, http.StatusUnauthorized, nil, err.Error())
			c.Abort()
			return
		}

		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			dto.JSON(c, http.StatusUnauthorized, nil, "Invalid token")
			c.Abort()
			return
		}
		if claims["token_type"] != "access" {
			dto.JSON(c, http.StatusUnauthorized, nil, "Invalid token")
			c.Abort()
			return
		}
		c.Set("user", claims)
		c.Next()
	}
}
