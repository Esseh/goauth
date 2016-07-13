package goauth
import (
	"time"
	"net/http"
	"google.golang.org/appengine/memcache"
	"crypto/sha256"
	"encoding/base64"
	"google.golang.org/appengine"
)

func crossSiteInitialize(res http.ResponseWriter,req *http.Request, v string){
	switch ClientType{
		case "override":
			CrossSiteInitialize(res,req)
		case "appengine":
			memcache.Set(appengine.NewContext(req), &memcache.Item{
				Key: v,
				Value: []byte("s"),
				Expiration: time.Duration(time.Minute),
			})			
		default:
			h := sha256.New()
			h.Write([]byte(v))
			encoded := base64.URLEncoding.EncodeToString(h.Sum(nil))

			http.SetCookie(res,&http.Cookie{
				Name: "goauth",
				Value: encoded,
				Expires: time.Now().Add(time.Minute),
				Domain: req.URL.Host,
			})		
	}
}


func crossSiteResolve(res http.ResponseWriter,req *http.Request) error {
	switch ClientType{
		case "override":
			return CrossSiteResolve(res,req)
		case "appengine":
			ctx := appengine.NewContext(req)
			_ , memErr := memcache.Get(ctx, req.FormValue("state"))
			if memErr != nil { return ErrCrossSite }
		default:
			cookie, cookErr := req.Cookie("goauth")
			if cookErr != nil {
				return ErrCrossSite
			}
			
			h := sha256.New()
			h.Write([]byte(req.FormValue("state")))
			stateValue := base64.URLEncoding.EncodeToString(h.Sum(nil))
			
			if len(cookie.Value) < 18 || stateValue != cookie.Value {
				return ErrCrossSite	
			}
	}
	return nil
}