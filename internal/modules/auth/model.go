package auth

import (
	"time"

	"gorm.io/gorm"
)

type Role string

var (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
	RoleSuper Role = "super"
)

type User struct {
	gorm.Model
	FirstName       string     `gorm:"column:first_name"`
	LastName        string     `gorm:"column:last_name"`
	Phone           *string    `gorm:"column:phone;default:null;uniqueIndex"`
	Email           *string    `gorm:"column:email;default:null;uniqueIndex"`
	UserName        *string    `gorm:"column:username;uniqueIndex;default:null"`
	Balance         int        `gorm:"column:balance"`
	TemplateBalance string     `gorm:"column:template_balance;default:0"`
	IsSuperuser     *bool      `gorm:"column:is_superuser;default:false"`
	IsStaff         *bool      `gorm:"column:is_staff;default:false"`
	IsActive        *bool      `gorm:"column:is_active;default:true"`
	DateJoined      *time.Time `gorm:"column:date_joined"`
	Password        string     `gorm:"column:password"`
	ValidatedAT     *time.Time `gorm:"column:validated_at"`
	Role            Role       `gorm:"column:role;default:user"`
}

func (*User) TableName() string {
	return "accounts_user"
}

type Otp struct {
	gorm.Model
	Phone string    `gorm:"phone;unique"`
	Code  string    `gorm:"code"`
	Exp   time.Time `gorm:"exp"`
}

func (*Otp) TableName() string {
	return "otp"
}
