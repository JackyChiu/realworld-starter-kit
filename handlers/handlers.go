package handlers

import (
	"log"

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
