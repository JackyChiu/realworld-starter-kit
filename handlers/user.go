package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JackyChiu/realworld-starter-kit/models"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Token    string `json:"token"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}

type UserJSON struct {
	User *User `json:"user"`
}

func (h *Handler) UsersHandler(w http.ResponseWriter, r *http.Request) {
	router := NewRouter(h.Logger)

	router.AddRoute(`users/?`, http.MethodPost, h.registerUser)
	router.AddRoute(`users/login/?`, http.MethodPost, h.loginUser)

	router.DebugMode(true)
	router.ServeHTTP(w, r)
}

func (h *Handler) getCurrentUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var u = &models.User{}
		ctx := r.Context()

		if claim, _ := h.JWT.CheckRequest(r); claim != nil {
			// Check also that user exists and prevent old token usage
			// to gain privillege access.
			if u, err = h.DB.FindUserByUsername(claim.Username); err != nil {
				http.Error(w, fmt.Sprint("User with username", claim.Username, "doesn't exist !"), http.StatusUnauthorized)
				return
			}
			ctx = context.WithValue(ctx, Claim, claim)
		}

		ctx = context.WithValue(ctx, CurrentUser, u)

		r = r.WithContext(ctx)
		next(w, r)
	}
}

func (h *Handler) registerUser(w http.ResponseWriter, r *http.Request) {
	body := struct {
		User struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"user"`
	}{}
	u := &body.User

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return
	}
	defer r.Body.Close()

	m, err := models.NewUser(u.Email, u.Username, u.Password)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	err = h.DB.CreateUser(m)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	res := &UserJSON{
		&User{
			Username: m.Username,
			Email:    m.Email,
			Token:    h.JWT.NewToken(m.Username),
		},
	}
	json.NewEncoder(w).Encode(res)
}
func (h *Handler) loginUser(w http.ResponseWriter, r *http.Request) {
	body := struct {
		User struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"user"`
	}{}
	u := &body.User

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	m, err := h.DB.FindUserByEmail(u.Email)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	match := m.MatchPassword(u.Password)
	if !match {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	res := &UserJSON{
		&User{
			Username: m.Username,
			Email:    m.Email,
			Token:    h.JWT.NewToken(m.Username),
			Bio:      m.Bio,
			Image:    m.Image,
		},
	}
	json.NewEncoder(w).Encode(res)
}
