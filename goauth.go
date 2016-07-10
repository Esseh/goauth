//////////////////////////////////////////////////////////////////////////////////
// goauth
/// blackboxed OAuth interactions.
//////////////////////////////////////////////////////////////////////////////////
package goauth
import(
	"net/url"
	"io/ioutil"
	"encoding/json"
	"fmt"
	"google.golang.org/appengine/urlfetch"	
	"net/http"
	"strings"
	"google.golang.org/appengine"
	"errors"
	"google.golang.org/appengine/memcache"
	"time"
	"github.com/nu7hatch/gouuid"
)

var(
	//////////////////////////////////////////////////////////////////////////////////
	// ErrBadToken is given if the type assertion in a recieve fails.
	//////////////////////////////////////////////////////////////////////////////////
	ErrBadToken = errors.New("Token Error: Invalid Token Used. \nDid you remember to pass it in as a pointer?")
	//////////////////////////////////////////////////////////////////////////////////
	// ErrCrossSite is given if states are invalid between send/recieve.
	//////////////////////////////////////////////////////////////////////////////////
	ErrCrossSite= errors.New("Error: Terminate Request, Cross Site Attack Detected")
	//////////////////////////////////////////////////////////////////////////////////
	// ErrNoData is given if 1 or more pieces of data were expected and 0 were recieved.
	//////////////////////////////////////////////////////////////////////////////////
	ErrNoData = errors.New("Error: No Data Found")
)

type GoogleToken struct {
	AZP 			string `json:"azp"`
	AUD 			string `json:"aud"`
	SUB 			string `json:"sub"`
	Scope 			string `json:"scope"`
	EXP 			string `json:"exp"`
	ExpiresIn 		string `json:"expires_in"`
	Email 			string `json:"email"`
	EmailVerified 	string `json:"email_verified"`
	AccessType 		string `json:"access_type"`
	State			string
}

type DropboxToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	UID         string `json:"uid"`
	State		string
}

type GitHubToken struct {
	Email    string
	Verified bool
	Primary  bool
	State 	 string
}

//////////////////////////////////////////////////////////////////////////////////
// Send if a multiplexer function that based on the token type will choose
// the correct function to execute for the first step of the OAuth handshake.
//////////////////////////////////////////////////////////////////////////////////
func Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string, model interface{}){
	switch model.(type){
		case *DropboxToken:
			dropboxSend(res, req, redirect, clientID)
		case *GitHubToken:
			githubSend(res, req, redirect, clientID)
		case *GoogleToken:
			googleSend(res, req, redirect, clientID)
	}
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve is a multiplexer function, based on the token type it will use the 
// appropriate function to get the OAuth token.
//////////////////////////////////////////////////////////////////////////////////
func Recieve(req *http.Request, redirect ,clientID, secretID string, token interface{}) error {
	switch token.(type){
		case *DropboxToken:
			return dropboxRecieve(req, redirect ,clientID, secretID, token.(*DropboxToken))
		case *GitHubToken:
			return githubRecieve(req, redirect ,clientID, secretID, token.(*GitHubToken))
		case *GoogleToken:
			return googleRecieve(req, redirect ,clientID, secretID, token.(*GoogleToken))
	}
	return ErrBadToken
}

// An internal struct for a step of the google OAuth process.
type googleData struct {
	AccessToken string `json:"access_token"`
	IDToken		string `json:"id_token"`
	ExpiresIn   int64 `json:"expires_in"`
	TokenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

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
// Send for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
func googleSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(req,redirect,clientID)
	values.Add("scope", "openid email")
	http.Redirect(res, req, fmt.Sprintf("https://accounts.google.com/o/oauth2/auth?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Send for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func dropboxSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(req,redirect,clientID)
	http.Redirect(res, req, "https://www.dropbox.com/1/oauth2/authorize?"+values.Encode(), http.StatusSeeOther)
}

//////////////////////////////////////////////////////////////////////////////////
// Send for Github OAuth
//////////////////////////////////////////////////////////////////////////////////	
func githubSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(req,redirect,clientID)
	values.Add("scope", "user:email")
	http.Redirect(res, req, fmt.Sprintf("https://github.com/login/oauth/authorize?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
func googleRecieve(req *http.Request, redirect ,googleid, googlesecretid string, token *GoogleToken) error {
	ctx := appengine.NewContext(req)
	
	_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { return ErrCrossSite }
	
	code := req.FormValue("code")
	v := url.Values{}
	v.Add("code", code)
	v.Add("client_id", googleid)
	v.Add("client_secret", googlesecretid)
	v.Add("redirect_uri", redirect)
	v.Add("grant_type","authorization_code")
	client := urlfetch.Client(ctx)
	res, err := client.PostForm("https://www.googleapis.com/oauth2/v4/token", v)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var data googleData
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return err
	}
	newclient := urlfetch.Client(ctx)
	newresponse, err := newclient.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+data.AccessToken)
	if err != nil { 
		return err
	}	

	defer newresponse.Body.Close()
	var trueToken GoogleToken
	err = json.NewDecoder(newresponse.Body).Decode(&trueToken)
	if err != nil { 
		return err	
	}		
	*token = trueToken
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}


	


func requiredRecieve(req *http.Request, clientID, secretID, redirect, src string) (*http.Response, error) {
	ctx := appengine.NewContext(req)
	values := make(url.Values)
	_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { return &http.Response{},ErrCrossSite }
	values.Add("code", req.FormValue("code"))
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", secretID)
	values.Add("redirect_uri", redirect)	
	return urlfetch.Client(ctx).PostForm(src, values)
}

func extractValue(res *http.Response, data interface{}) error {
	defer res.Body.Close()
	err := json.NewDecoder(res.Body).Decode(data)
	if err != nil {
		return err
	}
	return nil 
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func dropboxRecieve(req *http.Request, redirect ,clientID, secretID string, token *DropboxToken) error {
	res, err := requiredRecieve(req,clientID,secretID,redirect,"https://api.dropbox.com/1/oauth2/token") 
	if err != nil { return err }
	var data DropboxToken
	err = extractValue(res,&data)
	if err != nil { return err }
	*token = data
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}	
	
//////////////////////////////////////////////////////////////////////////////////
// Recieve for Github OAuth
/// 
//////////////////////////////////////////////////////////////////////////////////	
func githubRecieve(req *http.Request, redirect ,clientID, secretID string, token *GitHubToken) error {
	ctx := appengine.NewContext(req)	
	
	_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { return ErrCrossSite }
	
	values := make(url.Values)
	values.Add("client_id", clientID)
	values.Add("client_secret", secretID)
	values.Add("code", req.FormValue("code"))
	values.Add("state", req.FormValue("redirect"))

	client := urlfetch.Client(ctx)
	response0, err := client.PostForm("https://github.com/login/oauth/access_token", values)
	if err != nil {
		return err
	}
	defer response0.Body.Close()

	bs, err := ioutil.ReadAll(response0.Body)
	if err != nil {
		return err
	}

	values, err = url.ParseQuery(string(bs))
	if err != nil { return err }
	accessToken := values.Get("access_token")

	client2 := urlfetch.Client(ctx)
	response, err := client2.Get("https://api.github.com/user/emails?access_token=" + accessToken)
	if err != nil { return err }

	var data []GitHubToken
	err = extractValue(response,&data)
	if err != nil { return err }	
	if len(data) == 0 { return ErrNoData }

	*token = data[0]
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}