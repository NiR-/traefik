package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/urfave/negroni"
)

func NewMiddleware(config map[string]interface{}) (negroni.Handler, error) {
	if _, ok := config["keyfile"]; !ok {
		return nil, fmt.Errorf("no keyfile specified")
	}

	keyfile := config["keyfile"].(string)
	fileContent, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %s", keyfile, err.Error())
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(fileContent)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %s", keyfile, err.Error())
	}

	return jwtPlugin{
		key:       key,
		jwtParser: jwt.Parser{},
	}, nil
}

type jwtPlugin struct {
	key       *rsa.PublicKey
	jwtParser jwt.Parser
}

func (p jwtPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		write401(w)
		return
	}

	if strings.HasPrefix(authHeader, "Bearer ") == false {
		write401(w)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := p.jwtParser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return p.key, nil
	})
	if err != nil {
		write401(w)
		return
	}

	claimsJson, err := json.Marshal(token.Claims)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(""))
		return
	}

	r.Header.Set("X-JWT-Claims", string(claimsJson[:]))

	next(w, r)
}

func write401(w http.ResponseWriter) {
	w.Header().Set("WWWW-Authentiate", "bearer")
	w.WriteHeader(401)
	w.Write([]byte(""))
}
