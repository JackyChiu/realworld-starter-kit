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

	router.AddRoute(
		`users/?`,
		http.MethodPost,
		h.registerUser,
	)

	router.AddRoute(
		`users/login/?`,
		http.MethodPost,
		h.loginUser,
	)

	router.AddRoute(
		`users/?`,
		http.MethodGet,
		h.getCurrentUser(h.currentUser),
	)

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
			ctx = context.WithValue(ctx, claimKey, claim)
		}

		ctx = context.WithValue(ctx, currentUserKey, u)

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
	bodyUser := &body.User

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return
	}
	defer r.Body.Close()

	u, err := models.NewUser(bodyUser.Email, bodyUser.Username, bodyUser.Password)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	err = h.DB.CreateUser(u)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	res := &UserJSON{
		&User{
			Username: u.Username,
			Email:    u.Email,
			Token:    h.JWT.NewToken(u.Username),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (h *Handler) loginUser(w http.ResponseWriter, r *http.Request) {
	body := struct {
		User struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"user"`
	}{}
	bodyUser := &body.User

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	u, err := h.DB.FindUserByEmail(bodyUser.Email)
	if err != nil {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	match := u.MatchPassword(bodyUser.Password)
	if !match {
		// TODO: Error JSON
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	res := &UserJSON{
		&User{
			Username: u.Username,
			Email:    u.Email,
			Token:    h.JWT.NewToken(u.Username),
			Bio:      u.Bio,
			Image:    u.Image,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (h *Handler) currentUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	u := ctx.Value(currentUserKey).(*models.User)

	res := &UserJSON{
		&User{
			Username: u.Username,
			Email:    u.Email,
			Token:    h.JWT.NewToken(u.Username),
			Bio:      u.Bio,
			Image:    u.Image,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
