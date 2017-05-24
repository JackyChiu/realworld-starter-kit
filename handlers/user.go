package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JackyChiu/realworld-starter-kit/models"
)

// User is the user json object for responses
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Token    string `json:"token"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}

// UserJSON is the wrapper around User to give it a key "user"
type UserJSON struct {
	User *User `json:"user"`
}

// UserHandler handles the user routes
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

// getCurrentUser is a middleware that extracts the current user into context
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

// POST /user
// regiesterUser adds a new user to the database and response with the new user
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

	u, errs := models.NewUser(bodyUser.Email, bodyUser.Username, bodyUser.Password)
	if errs != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(&errorJSON{errs})
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

// POST /user/login
// loginUser returns an user according to the credentials provided
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

// GET /user
// currentUser responds with the current user
func (h *Handler) currentUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	u := ctx.Value(currentUserKey).(*models.User)

	res := &UserJSON{
		&User{
			Username: u.Username,
			Email:    u.Email,
			// TODO: Use same token that was provided?
			Token: h.JWT.NewToken(u.Username),
			Bio:   u.Bio,
			Image: u.Image,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
