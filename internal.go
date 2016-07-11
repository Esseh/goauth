package goauth
import(
	"net/url"
	"encoding/json"
	"google.golang.org/appengine/urlfetch"	
	"google.golang.org/appengine/log"
	"net/http"
	"strings"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
	"time"
	"github.com/nu7hatch/gouuid"
)

//////////////////////////////////////////////////////////////////////////////////
// Required Parameters - Also performs first half of check against cross-site attacks
//////////////////////////////////////////////////////////////////////////////////
func requiredSend(req *http.Request,redirect, clientID string) url.Values {
	values := make(url.Values)
	values.Add("client_id",clientID)
	values.Add("redirect_uri",redirect)
	values.Add("response_type","code")
	id , _ := uuid.NewV4()
	values.Add("state", id.String() + "](|)[" + req.FormValue("state"))
	memcache.Set(appengine.NewContext(req), &memcache.Item{
		Key: values.Get("state"),
		Value: []byte("s"),
		Expiration: time.Duration(time.Minute),
	})
	return values
}


//////////////////////////////////////////////////////////////////////////////////
// Makes the required recieve request for an access token.
// ASSUMES: I am getting JSON back.
// I can add in an Accept: application/json
// but I have only used that for Github which ignored it.
//////////////////////////////////////////////////////////////////////////////////
func requiredRecieve(req *http.Request, clientID, secretID, redirect, src string) (*http.Response, error) {
	ctx := appengine.NewContext(req)
	values := make(url.Values)
	_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { 
		log.Errorf(ctx,"\nGENERAL RECIEVE ERROR 1\n",memErr)
		return &http.Response{},ErrCrossSite 
	}
	values.Add("code", req.FormValue("code"))
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", secretID)
	values.Add("redirect_uri", redirect)	

	client := urlfetch.Client(ctx)
	reqq, err := http.NewRequest(http.MethodPost, src, strings.NewReader(values.Encode()))
	if err != nil { 
		return &http.Response{}, err 
		log.Errorf(ctx,"\nINTERNAL ERROR 2\n",err)
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