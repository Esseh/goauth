package goauth
import (
	"time"
	"net/http"
	"crypto/sha256"
	"encoding/base64"
)

//////////////////////////////////////////////////////////////////////////////////
// Stores some piece of information in order to check it later.
//////////////////////////////////////////////////////////////////////////////////
func crossSiteInitialize(res http.ResponseWriter,req *http.Request, v string){
	switch ClientType{
		case "override":
			CrossSiteInitialize(res,req, v)
		case "appengine":
			appengineCrossSiteInitialize(res, req, v)
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


//////////////////////////////////////////////////////////////////////////////////
// Checks the information previously stored to check against cross site attacks. 
//////////////////////////////////////////////////////////////////////////////////
func crossSiteResolve(res http.ResponseWriter,req *http.Request) error {
	switch ClientType{
		case "override":
			return CrossSiteResolve(res,req)
		case "appengine":
			return appengineCrossSiteResolve(res,req)
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