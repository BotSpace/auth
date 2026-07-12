package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/JscorpTech/auth/docs"
	"github.com/JscorpTech/auth/internal/config"
	"github.com/JscorpTech/auth/internal/modules/auth"
	authHttp "github.com/JscorpTech/auth/internal/modules/auth/delivery/http"
	"github.com/JscorpTech/auth/internal/services"
	"github.com/JscorpTech/auth/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// @title           Swagger Example API
// @version         1.0
// @description     This is a sample server celler server.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.basic  BasicAuth

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/
func main() {

	logger, _ := zap.NewDevelopment()
	err := godotenv.Load()
	if err != nil {
		logger.Info(".env load error")
	}

	cfg, err := config.NewConfig()
	if err != nil {
		logger.Fatal("invalid configuration", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var driver gorm.Dialector
	if cfg.DatabaseType == "postgres" {
		driver = postgres.Open(cfg.DatabaseDsn)
	} else {
		driver = sqlite.Open("db.sqlite3")
	}

	db, err := gorm.Open(driver, &gorm.Config{})
	if err != nil {
		panic("failed to connect databse")
	}

	// migrations
	db.AutoMigrate(&auth.User{})
	db.AutoMigrate(&auth.Otp{})

	router := gin.Default()

	// Prometheus metrics endpoint (default Go runtime + process collectors).
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	router.GET("/api/v1/auth/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	api := router.Group("/api/v1/auth")

	limiter := utils.NewRateLimiter(ctx, logger, 100)

	api.Use(func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.Allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"status": false,
				"error":  "Rate limit exceeded",
			})
			return
		}

		c.Next()
	})

	// Auth routes
	authRepository := auth.NewAuthRepository(db)
	authUsecase := auth.NewAuthUsecase(authRepository, cfg, logger)
	authHandler := authHttp.NewAuthHandler(authUsecase, logger)
	authHttp.RegisterAuthRoutes(cfg, api, authHandler)

	go services.OtpClean(ctx, logger, authRepository)

	srv := http.Server{
		Handler: router,
		Addr:    cfg.Addr,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		logger.Info("Server ishga tushdi 🚀 " + cfg.Addr)
		if err := srv.ListenAndServe(); err != nil {
			logger.Info("Server to'xtatildi", zap.Error(err))
		}
	}()

	<-stop
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Serverni o'chirishda xatolik yuz berdi", zap.Error(err))
	}
	logger.Info("Server muvaffaqiyatli to'xtatildi")
}
