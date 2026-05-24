package auth

import (
	"context"
	"errors"
	"time"

	"github.com/JscorpTech/auth/internal/config"
	"github.com/JscorpTech/auth/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"google.golang.org/api/idtoken"
	"gorm.io/gorm"
)

type AuthUsecase interface {
	Login(context.Context, string, string) (*User, error)
	Register(context.Context, *User) (*User, error)
	IsExists(context.Context, string) bool
	GetUserByID(context.Context, int64) (*User, error)
	ValidateToken(string) (*jwt.MapClaims, error)
	AccessToken(*User) string
	RefreshToken(*User) string
	SendOtp(context.Context, string) error
	ValidateOtp(context.Context, string, string) bool
	IsConfirm(context.Context, *User) bool
	GetUserByPhone(context.Context, string) (*User, error)
	Confirm(context.Context, *User)
	ValidateGoogleIDToken(context.Context, string) (*idtoken.Payload, error)
	GoogleAuth(context.Context, string) (*User, error)
}

type AuthUsecaseImpl struct {
	repo   AuthRepository
	cfg    *config.Config
	logger *zap.Logger
}

func NewAuthUsecase(repo AuthRepository, cfg *config.Config, logger *zap.Logger) AuthUsecase {
	return &AuthUsecaseImpl{
		repo:   repo,
		cfg:    cfg,
		logger: logger,
	}
}

func (a *AuthUsecaseImpl) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return a.repo.GetID(ctx, id)
}

func (a *AuthUsecaseImpl) GoogleAuth(ctx context.Context, idToken string) (*User, error) {
	payload, err := a.ValidateGoogleIDToken(ctx, idToken)
	if err != nil {
		return nil, err
	}
	email, ok := payload.Claims["email"].(string)
	if !ok {
		return nil, errors.New("email claim not found in ID token")
	}
	userInstance, err := a.repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			firstName, _ := payload.Claims["given_name"].(string)
			lastName, _ := payload.Claims["family_name"].(string)
			now := time.Now()
			isSuperUser := false
			isStaff := false
			isActive := true
			dateJoined := time.Now()
			user := &User{
				Email:       &email,
				FirstName:   firstName,
				LastName:    lastName,
				IsSuperuser: &isSuperUser,
				IsStaff:     &isStaff,
				IsActive:    &isActive,
				DateJoined:  &dateJoined,
				ValidatedAT: &now,
			}
			if userInstance, err = a.repo.Create(ctx, user); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return userInstance, nil
}

func (a *AuthUsecaseImpl) ValidateGoogleIDToken(ctx context.Context, idToken string) (*idtoken.Payload, error) {
	claims, err := idtoken.Validate(ctx, idToken, a.cfg.GoogleClientID)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (a *AuthUsecaseImpl) IsConfirm(ctx context.Context, user *User) bool {
	return user.ValidatedAT != nil
}

func (a *AuthUsecaseImpl) ValidateToken(token string) (*jwt.MapClaims, error) {
	claims, err := utils.VerifyJWT(token, a.cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	if claims["type"] != "refresh" {
		return nil, ErrInvalidRefreshToken
	}
	return &claims, nil
}

func (a *AuthUsecaseImpl) Login(ctx context.Context, phone string, password string) (*User, error) {
	user, err := a.repo.GetByPhone(ctx, phone)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentions
		}
		return nil, err
	}
	if !a.IsConfirm(ctx, user) {
		return nil, ErrPhoneNumberNotConfirmed
	}

	if res := utils.CheckPasswordHash(password, user.Password); !res {
		return nil, ErrInvalidPassword
	}
	return user, nil
}

func (a *AuthUsecaseImpl) IsExists(ctx context.Context, phone string) bool {
	return a.repo.IsExists(ctx, phone)
}

func (a *AuthUsecaseImpl) Register(ctx context.Context, user *User) (*User, error) {
	userInstance, err := a.repo.GetByPhone(ctx, *user.Phone)
	if err == nil && a.IsConfirm(ctx, userInstance) {
		return nil, ErrUserAlreadyExists
	}
	if err != nil {
		userInstance, err = a.repo.Create(ctx, user)
	}
	if err := a.SendOtp(ctx, *user.Phone); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return userInstance, nil
}

func (a *AuthUsecaseImpl) AccessToken(user *User) string {
	claims := jwt.MapClaims{
		"user_id":      user.ID,
		"exp":          time.Now().Add(time.Minute * time.Duration(a.cfg.AccessExp)).Unix(),
		"token_type":   "access",
		"jti":          utils.RandomString(20, "1234567890"),
		"role":         user.Role,
	}
	token, err := utils.CreateJWT(claims, a.cfg.PrivateKey)
	if err != nil {
		a.logger.Error("create access token error", zap.Error(err))
		return ""
	}
	return token
}

func (a *AuthUsecaseImpl) RefreshToken(user *User) string {
	claims := jwt.MapClaims{
		"user_id":    user.ID,
		"exp":        time.Now().Add(time.Minute * time.Duration(a.cfg.RefreshExp)).Unix(),
		"token_type": "refresh",
		"jti":        utils.RandomString(20, "1234567890"),
		"role":       user.Role,
	}
	token, err := utils.CreateJWT(claims, a.cfg.PrivateKey)
	if err != nil {
		a.logger.Error("create refresh token error", zap.Error(err))
		return ""
	}
	return token
}

func (a *AuthUsecaseImpl) SendOtp(ctx context.Context, phone string) error {
	code := utils.RandomOtp(6)
	a.logger.Info("New otp", zap.String("otp", code))
	otp, err := a.repo.GetOtpByPhone(ctx, phone)
	if err != nil {
		otp, err = a.repo.CreateOtp(ctx, phone, code)
		if err != nil {
			return err
		}
	} else if time.Since(otp.UpdatedAt) < time.Minute*2 {
		return ErrRateLimit
	}
	if err := a.repo.UpdateOtp(ctx, phone, code); err != nil {
		return err
	}
	return nil
}

func (a *AuthUsecaseImpl) ValidateOtp(ctx context.Context, phone string, otp string) bool {
	otpInstance, err := a.repo.GetOtp(ctx, phone, otp)
	if err != nil {
		a.logger.Info("invalid otp", zap.Error(err))
		return false
	}
	a.repo.DeleteOtp(ctx, otpInstance)
	return true
}

func (a *AuthUsecaseImpl) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	return a.repo.GetByPhone(ctx, phone)
}

func (a *AuthUsecaseImpl) Confirm(ctx context.Context, user *User) {
	a.repo.Update(ctx, user, map[string]any{
		"validated_at": time.Now(),
	})
}
