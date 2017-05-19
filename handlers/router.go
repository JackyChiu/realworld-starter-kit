package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
)

type Route struct {
	Pattern        string
	ActionHandlers map[string]http.Handler
}

type Router struct {
	http.Handler
	routes []Route
	logger *log.Logger
	debug  bool
}

const (
	currentUserKey    = "current_user"
	fetchedArticleKey = "article"
	claimKey          = "claim"
)

func NewRouter(logger *log.Logger) *Router {
	debug, err := strconv.ParseBool(os.Getenv("DEBUG"))
	if err != nil {
		debug = false
	}

	return &Router{
		routes: make([]Route, 0),
		logger: logger,
		debug:  debug,
	}
}

// AddRoute add a new route to the router for the given pattern, method and http.Handler
// Example:
// h:=http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
// 	id:=r.Context().Value("id").(int)
//})
//
// r :=  router.NewRouter(l)
// To handle /blog/:id
// r.AddRoute(`\/blog\/(?P<id>[0-9]+$`, h)
// The id will be availabl in the http.Request Context passed to your handler
func (r *Router) AddRoute(pattern string, method string, handler http.HandlerFunc) {
	var found = false
	for _, route := range r.routes {
		if route.Pattern == pattern {
			found = true
			// Maybe return an error and not replace the old route
			route.ActionHandlers[method] = handler
		}
	}

	if !found {
		r.routes = append(r.routes, Route{
			Pattern: pattern,
			ActionHandlers: map[string]http.Handler{
				method: handler,
			},
		})
	}
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, route := range router.routes {
		if matched, _ := regexp.MatchString(route.Pattern, r.URL.Path); matched {
			if h, registered := route.ActionHandlers[r.Method]; registered {
				if router.debug {
					router.trace(r)
				}
				r = r.WithContext(buildContext(route.Pattern, r))
				h.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Private Method															 //
///////////////////////////////////////////////////////////////////////////////

// buildContext extracl all reqex named matches from the request url path
// and make it available through the request context
//
// Example:
// Pattern: "\/blog\/(?P<id>[0-9]+)$"
// Match URL: /blog/123
//
// Context will contain a key 'id' with the value '123'
func buildContext(pattern string, r *http.Request) context.Context {
	re := regexp.MustCompile(pattern)
	n1 := re.SubexpNames()
	r2 := re.FindAllStringSubmatch(r.URL.Path, -1)

	ctx := r.Context()

	if len(r2) > 0 {
		for i, n := range r2[0] {
			if n1[i] != "" {
				ctx = context.WithValue(ctx, n1[i], n)
			}
		}
	}
	return ctx
}

func (r *Router) trace(req *http.Request) {
	debugLine := fmt.Sprintf("%v %v %v", req.RemoteAddr, req.Method, req.URL.Path)
	r.logger.Println(debugLine)
}
