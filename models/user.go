package models

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserStorer interface {
	CreateUser(*User) error
	FindUserByEmail(string) (*User, error)
}

type User struct {
	ID        int
	CreatedAt time.Time
	Username  string
	Email     string
	Password  string
	Bio       string
	Image     string
}

func (u *User) MatchPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func EncryptPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func NewUser(email, username, password string) (*User, ValidationErrors) {
	errs := ValidationErrors{}
	if email == "" {
		errs["email"] = []string{EMPTY_MSG}
	}
	if username == "" {
		errs["username"] = []string{EMPTY_MSG}
	}
	if password == "" {
		errs["password"] = []string{EMPTY_MSG}
	}
	if errs != nil {
		return nil, errs
	}
	return &User{
		Email:    email,
		Username: username,
		Password: EncryptPassword(password),
	}, nil
}

func (db *DB) CreateUser(user *User) error {
	u := User{}

	db.Find(&u, "email = ?", user.Email)
	if u != (User{}) {
		return fmt.Errorf("Email already exisits")
	}

	db.Find(&u, "username = ?", user.Username)
	if u != (User{}) {
		return fmt.Errorf("Username already exisits")
	}

	db.Create(user)

	return nil
}

func (db *DB) FindUserByEmail(email string) (*User, error) {
	u := User{}
	db.Find(&u, "email = ?", email)
	if u == (User{}) {
		return nil, fmt.Errorf("No user found with userame: ", email)
	}
	return &u, nil
}
