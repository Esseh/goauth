package goauth
import(
	"net/url"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"google.golang.org/appengine/urlfetch"	
	"google.golang.org/appengine/log"
	"net/http"
	"strings"
	"google.golang.org/appengine"
	//"google.golang.org/appengine/memcache"
	"time"
	"github.com/nu7hatch/gouuid"
)

//////////////////////////////////////////////////////////////////////////////////
// Required Parameters - Also performs first half of check against cross-site attacks
//////////////////////////////////////////////////////////////////////////////////
func requiredSend(res http.ResponseWriter,req *http.Request,redirect, clientID string) url.Values {
	values := make(url.Values)
	values.Add("client_id",clientID)
	values.Add("redirect_uri",redirect)
	values.Add("response_type","code")
	id , _ := uuid.NewV4()
	values.Add("state", id.String() + "](|)[" + req.FormValue("state"))

	h := sha256.New()
	h.Write([]byte(values.Get("state")))
	encoded := base64.URLEncoding.EncodeToString(h.Sum(nil))

	http.SetCookie(res,&http.Cookie{
		Name: "goauth",
		Value: encoded,
		Expires: time.Now().Add(time.Minute),
		Domain: req.URL.Host,
	})
	/*memcache.Set(appengine.NewContext(req), &memcache.Item{
		Key: values.Get("state"),
		Value: []byte("s"),
		Expiration: time.Duration(time.Minute),
	})*/
	
	
	return values
}


//////////////////////////////////////////////////////////////////////////////////
// Makes the required recieve request for an access token.
// ASSUMES: I am getting JSON back.
// I can add in an Accept: application/json
// but I have only used that for Github which ignored it.
//////////////////////////////////////////////////////////////////////////////////
func requiredRecieve(res http.ResponseWriter, req *http.Request, clientID, secretID, redirect, src string) (*http.Response, error) {
	ctx := appengine.NewContext(req)
	values := make(url.Values)

	cookie, cookErr := req.Cookie("goauth")
	if cookErr != nil {
		return &http.Response{},ErrCrossSite
	}
	
	h := sha256.New()
	h.Write([]byte(req.FormValue("state")))
	stateValue := base64.URLEncoding.EncodeToString(h.Sum(nil))
	
	if len(cookie.Value) < 18 || stateValue != cookie.Value {
		return &http.Response{},ErrCrossSite	
	}
	
	/*_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { return &http.Response{},ErrCrossSite }*/
	
	values.Add("code", req.FormValue("code"))
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", secretID)
	values.Add("redirect_uri", redirect)	

	client := internalClient(req)
	reqq, err := http.NewRequest("POST", src, strings.NewReader(values.Encode()))
	if err != nil { 
		return &http.Response{}, err 
		log.Errorf(ctx,"Problem Making Request\n\n",err)
	}
	reqq.Header.Set("Accept","application/json")
	return client.Do(reqq)
}

//////////////////////////////////////////////////////////////////////////////////
// Uses reflection to extract a JSON object from a response into an input struct.
//////////////////////////////////////////////////////////////////////////////////
func extractValue(res *http.Response, data interface{}) error {
	defer res.Body.Close()
	err := json.NewDecoder(res.Body).Decode(data)
	if err != nil {
		return err
	}
	return nil 
}

func internalClient(req *http.Request) *http.Client{
	switch ClientType{
		case "override":
			return ClientOverride(req)
		case "appengine":
			return urlfetch.Client(appengine.NewContext(req))
	}
	return &http.Client{}
}