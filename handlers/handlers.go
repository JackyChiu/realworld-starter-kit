package handlers

import (
	"log"
	"net/http"

	"github.com/JackyChiu/realworld-starter-kit/auth"
	"github.com/JackyChiu/realworld-starter-kit/models"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type Handler struct {
	DB     models.Datastorer
	JWT    auth.Tokener
	Logger *log.Logger
}

func New(db *models.DB, jwt *auth.JWT, logger *log.Logger) *Handler {
	return &Handler{db, jwt, logger}
}

func (h *Handler) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if claim := r.Context().Value(Claim); claim != nil {
			if currentUser := r.Context().Value(CurrentUser).(*models.User); (currentUser == &models.User{}) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			} else {
				next.ServeHTTP(w, r)
			}
		} else {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}
