package models

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/Machiel/slugify"
	"github.com/jinzhu/gorm"
)

type ArticleStorer interface {
	CreateArticle(*Article) error
	DeleteArticle(*Article) error
	GetAllArticles() *gorm.DB
	GetAllArticlesAuthoredBy(string, int, int) ([]Article, error)
	GetAllArticlesFavoritedBy(string, int, int) ([]Article, error)
	GetAllArticlesWithTag(string, int, int) ([]Article, error)
	GetArticle(string) (*Article, error)
	FavoriteArticle(*User, *Article) error
	UnfavoriteArticle(*User, *Article) error
	FindUserByUsername(string) (*User, error)
	IsFavorited(int, int) bool
	IsFollowing(int, int) bool
	SaveArticle(*Article) error
	FilterAuthoredBy(*gorm.DB, interface{}) *gorm.DB
	FilterFavoritedBy(*gorm.DB, interface{}) *gorm.DB
	FilterByTag(*gorm.DB, interface{}) *gorm.DB
	Limit(*gorm.DB, interface{}) *gorm.DB
	Offset(*gorm.DB, interface{}) *gorm.DB
}

// Article the article model
type Article struct {
	ID             int
	Slug           string
	Title          string
	Description    string
	Body           string
	User           User
	UserID         int
	Tags           []Tag `gorm:"many2many:taggings;"`
	Favorites      []Favorite
	FavoritesCount int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

var (
	errorArticleAlreadyFavorited = errors.New("This article is already in your favorites !")
	errorArticleNotFavorited     = errors.New("Cannot remove this article from your favorites. This article is not in your favorites !")
)

const (
	defaultOffset = 0
	defaultLimit  = 20
)

// NewArticle returns a new Article instance.
func NewArticle(title string, description string, body string, user *User) *Article {
	return &Article{
		Title:       title,
		Description: description,
		Body:        body,
		User:        *user,
	}
}

// IsValid check if the article has a valid title, description and body
func (a *Article) IsValid() (bool, ValidationErrors) {
	var errs = ValidationErrors{}
	var valid = true

	if a.Title == "" {
		errs["title"] = []string{EMPTY_MSG}
		valid = false
	}

	if a.Description == "" {
		errs["description"] = []string{EMPTY_MSG}
		valid = false
	}

	if a.Body == "" {
		errs["body"] = []string{EMPTY_MSG}
		valid = false
	}

	return valid, errs
}

// IsOwnedBy check if the article is owned by the given username
func (a *Article) IsOwnedBy(username string) bool {
	return a.User.Username == username
}

// CreateArticle persist a new article
func (db *DB) CreateArticle(article *Article) (err error) {
	err = db.Create(&article).Error
	return
}

// DeleteArticle delete an article
// WARNING You must provide a primary key in the struct orherwise
// gorm will delete all article models.
func (db *DB) DeleteArticle(article *Article) (err error) {
	err = db.Delete(&article).Error
	return
}

// SaveArticle save/update an article to the database.
func (db *DB) SaveArticle(article *Article) (err error) {
	err = db.Save(&article).Error
	return
}

// GetArticle retrieve an article by it slug
func (db *DB) GetArticle(slug string) (*Article, error) {
	var article Article
	err := db.DB.Scopes(defaultArticleScope).First(&article, "slug = ?", slug).Error
	return &article, err
}

// GetAllArticles return a scope query to fetch all articles.
// You must call Find at the end to perform the query.
func (db *DB) GetAllArticles() *gorm.DB {
	return db.Scopes(defaultArticleScope)
}

// GetAllArticlesWithTag get all articles containings the given tag name.
func (db *DB) GetAllArticlesWithTag(tagName string, limit int, offset int) (articles []Article, err error) {
	scopedQuery := db.FilterByTag(db.Scopes(defaultArticleScope), tagName)
	scopedQuery = db.Limit(scopedQuery, limit)
	scopedQuery = db.Offset(scopedQuery, offset)
	err = scopedQuery.Find(&articles).Error
	return
}

// GetAllArticlesAuthoredBy get all articles authored by the given username
func (db *DB) GetAllArticlesAuthoredBy(username string, limit int, offset int) (articles []Article, err error) {
	scopedQuery := db.FilterAuthoredBy(db.Scopes(defaultArticleScope), username)
	scopedQuery = db.Limit(scopedQuery, limit)
	scopedQuery = db.Offset(scopedQuery, offset)
	err = scopedQuery.Find(&articles).Error
	return
}

// GetAllArticlesFavoritedBy get all article favorited by the given username
func (db *DB) GetAllArticlesFavoritedBy(username string, limit int, offset int) (articles []Article, err error) {
	scopedQuery := db.FilterFavoritedBy(db.Scopes(defaultArticleScope), username)
	scopedQuery = db.Limit(scopedQuery, limit)
	scopedQuery = db.Offset(scopedQuery, offset)
	err = scopedQuery.Find(&articles).Error
	return
}

// IsFavorited check if the given user ID favorited the given article ID
func (db *DB) IsFavorited(userID int, articleID int) bool {
	f := Favorite{ArticleID: articleID, UserID: userID}
	if db.Where(f).First(&f).RecordNotFound() {
		return false
	}
	return true
}

// IsFollowing check if the given userIDFrom follows userIDTo
func (db *DB) IsFollowing(userIDFrom int, userIDTo int) bool {
	// TODO
	return false
}

// FindUserByUsername find a user by its username
func (db *DB) FindUserByUsername(username string) (*User, error) {
	var user User
	err := db.First(&user, "username = ?", username).Error
	return &user, err
}

// FavoriteArticle add the article to the favorites of the given user
func (db *DB) FavoriteArticle(u *User, a *Article) error {
	var err error
	f := Favorite{UserID: u.ID, ArticleID: a.ID}

	if !db.IsFavorited(u.ID, a.ID) {
		err = db.Model(&a).Association("Favorites").Append(f).Error
	} else {
		err = errorArticleAlreadyFavorited
	}

	return err
}

// UnfavoriteArticle remove the article to the favorites of the given user
func (db *DB) UnfavoriteArticle(u *User, a *Article) error {
	var err error
	f := Favorite{}

	if !db.First(&f, Favorite{UserID: u.ID, ArticleID: a.ID}).RecordNotFound() {
		// We can't use the association mode because AfterCreate callbacks on favorite
		// will not be called and favorties_count will not be decremented
		// so we need to use Delete() directly.
		err = db.Delete(&f).Error
		// Reload the article reference, to update the favorites_count
		err = db.First(&a).Error
	} else {
		err = errorArticleNotFavorited
	}

	return err
}

// Callbacks

// BeforeCreate gorm callback
// Titile slugyfication
func (a *Article) BeforeCreate() (err error) {
	a.Slug = slugify.Slugify(a.Title)
	return
}

// BeforeUpdate gorm callback
// Titile slugyfication
func (a *Article) BeforeUpdate() (err error) {
	a.Slug = slugify.Slugify(a.Title)
	return
}

// FilterByTag filtering article by tag name
func (DB) FilterByTag(db *gorm.DB, value interface{}) *gorm.DB {
	var whereClause string
	var args interface{}
	var skip = true

	switch value.(type) {
	case url.Values:
		whereClause, args, skip = buildWhereClause("tags.name", "tag", value)
	default:
		whereClause, args, skip = buildWhereClause("tags.name", value)
	}

	if !skip {
		return db.Joins("JOIN taggings ON taggings.article_id = articles.id").
			Joins("JOIN tags ON tags.id = taggings.tag_id").
			Where(whereClause, args)
	}

	return db
}

// FilterAuthoredBy filtering article by author username
func (DB) FilterAuthoredBy(db *gorm.DB, value interface{}) *gorm.DB {
	var whereClause string
	var args interface{}
	var skip = true

	switch value.(type) {
	case url.Values:
		whereClause, args, skip = buildWhereClause("users.username", "author", value)
	default:
		whereClause, args, skip = buildWhereClause("users.username", value)
	}

	if !skip {
		return db.Joins("JOIN users ON users.id = articles.user_id").
			Where(whereClause, args)
	}

	return db
}

// FilterFavoritedBy filter articles favorited by user(s) username, value argument can be string|[]string|url.Values
// If a url.Values provided, it must contains a query string 'favorited' param name.
func (DB) FilterFavoritedBy(db *gorm.DB, value interface{}) *gorm.DB {
	var whereClause string
	var args interface{}
	var skip = true

	switch value.(type) {
	case url.Values:
		whereClause, args, skip = buildWhereClause("users.username", "favorited", value)
	default:
		whereClause, args, skip = buildWhereClause("users.username", value)
	}

	if !skip {
		var ids []int
		err := db.New().
			Model(&User{}).
			Where(whereClause, args).
			Pluck("id", &ids).Error

		if err != nil {
			return db
		}

		return db.Joins("JOIN favorites ON favorites.article_id = articles.id").
			Where("favorites.user_id IN (?)", ids)
	}

	return db
}

// Offset set the wanted offset (defaulf: 0) to an existing *gorm.DB instance.
func (DB) Offset(db *gorm.DB, offset interface{}) *gorm.DB {
	var offsetValue = offset

	switch offset.(type) {
	case url.Values:
		queryParams := offset.(url.Values)
		v := queryParams.Get("offset")

		if v != "" {
			intVal, err := strconv.Atoi(v)
			if err != nil {
				offsetValue = defaultOffset
			} else {
				offsetValue = intVal
			}
		} else {
			offsetValue = defaultOffset
		}
	}

	return db.Offset(offsetValue)
}

// Limit set the number of max articles to fetch (defaulf: 20) to an existing *gorm.DB instance.
func (DB) Limit(db *gorm.DB, limit interface{}) *gorm.DB {
	var limitValue = limit

	switch limit.(type) {
	case url.Values:
		queryParams := limit.(url.Values)
		v := queryParams.Get("limit")

		if v != "" {
			intVal, err := strconv.Atoi(v)
			if err != nil {
				limitValue = defaultLimit
			} else {
				limitValue = intVal
			}
		} else {
			limitValue = defaultLimit
		}
	}

	return db.Limit(limitValue)
}

///////////////////////////////////////////////////////////////////////////////
// Scopes															 		 //
///////////////////////////////////////////////////////////////////////////////

// Order articles by created_at DESC eager loading Tags and User
func defaultArticleScope(db *gorm.DB) *gorm.DB {
	return db.Order("articles.created_at desc").
		Preload("Tags").
		Preload("User")
}

///////////////////////////////////////////////////////////////////////////////
// Private Methods															 //
///////////////////////////////////////////////////////////////////////////////

func buildWhereClause(field string, vars ...interface{}) (string, interface{}, bool) {
	var whereClause, key string
	var args, value interface{}
	// skip determine if we apply or not the query
	// case for a string true if the value is empty
	// case for Slice true if slice length is equal to 0
	// case for a url.Values (map) if the value.Get(key) return an empty string
	var skip bool

	if len(vars) == 1 {
		// Case with primitive
		// buildWhereClause(field, value)
		value = vars[0]
	} else if len(vars) == 2 {
		// Case for an url.Values
		// buildWhereClause(field, key, value)
		key, value = vars[0].(string), vars[1]
	}

	switch value.(type) {
	case string:
		skip = (value.(string) == "")
		if !skip {
			whereClause = "%v = ?"
			args = value
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, sql.NullInt64:
		whereClause = "%v = ?"
		args = value
	case []int, []int8, []int16, []int32, []int64, []uint, []uint8, []uint16, []uint32, []uint64, []string, []interface{}:
		skip = reflect.ValueOf(value).Len() == 0
		if !skip {
			whereClause = "%v IN (?)"
			args = value
		}
	case url.Values:
		queryParams := value.(url.Values)
		v := queryParams.Get(key)
		skip = (v == "")
		if !skip {
			whereClause = "%v = ?"
			args = v
		}
	default:
		skip = true
	}

	if skip {
		return "", nil, skip
	}

	return fmt.Sprintf(whereClause, field), args, skip

}
