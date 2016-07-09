package goauth
import(
	"net/url"
	"io/ioutil"
	"encoding/json"
	"fmt"
	"google.golang.org/appengine/urlfetch"	
	"net/http"
	"google.golang.org/appengine"
)
/// GOAUTH
func GOOGLE_Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := make(url.Values)
	values.Add("client_id",clientID)
	values.Add("redirect_uri",redirect)
	values.Add("response_type","code")
	values.Add("scope", "openid email")
	values.Add("state", req.FormValue("redirect"))
	http.Redirect(res, req, fmt.Sprintf("https://accounts.google.com/o/oauth2/auth?%s",values.Encode()), 302)
}

func GOOGLE_recieve(req *http.Request, redirect ,googleid, googlesecretid string) (*GoogleToken, error) {
	ctx := appengine.NewContext(req)
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
		return &GoogleToken{}, err
	}
	defer res.Body.Close()
	var data googleData
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return &GoogleToken{}, err
	}
	newclient := urlfetch.Client(ctx)
	newresponse, err := newclient.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+data.AccessToken)
	if err != nil { 
		return &GoogleToken{}, err
	}	

	defer newresponse.Body.Close()
	var trueToken GoogleToken
	err = json.NewDecoder(newresponse.Body).Decode(&trueToken)
	if err != nil { 
		return &GoogleToken{}, err	
	}		
	
	return &trueToken, nil
}



func DROPBOX_recieve(req *http.Request, redirect ,ClientID, SecretID string) (*DropboxToken, error) {
	ctx := appengine.NewContext(req)
	v := url.Values{}
	v.Add("code", req.FormValue("code"))
	v.Add("grant_type", "authorization_code")
	v.Add("client_id", ClientID)
	v.Add("client_secret", SecretID)
	v.Add("redirect_uri", redirect)
	client := urlfetch.Client(ctx)
	res, err := client.PostForm("https://api.dropbox.com/1/oauth2/token", v)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var data DropboxToken
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func DROPBOX_Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	v := url.Values{}
	v.Add("response_type", "code")
	v.Add("client_id", clientID)
	v.Add("redirect_uri", redirect)
	v.Add("state", req.FormValue("redirect"))
	http.Redirect(res, req, "https://www.dropbox.com/1/oauth2/authorize?"+v.Encode(), http.StatusSeeOther)
}


type googleData struct {
	AccessToken string `json:"access_token"`
	IDToken		string `json:"id_token"`
	ExpiresIn   int64 `json:"expires_in"`
	TokenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

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
}

type DropboxToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	UID         string `json:"uid"`
}

type GitHubToken struct {
		Email    string
		Verified bool
		Primary  bool
	}
	
	
	
func GITHUB_recieve(req *http.Request, redirect ,ClientID, SecretID string) (*GitHubToken, error) {
	ctx := appengine.NewContext(req)	
	values := make(url.Values)
	values.Add("client_id", ClientID)
	values.Add("client_secret", SecretID)
	values.Add("code", req.FormValue("code"))
	values.Add("state", req.FormValue("redirect"))

	client := urlfetch.Client(ctx)
	response0, err := client.PostForm("https://github.com/login/oauth/access_token", values)
	if err != nil {
		return &GitHubToken{}, err
	}
	defer response0.Body.Close()

	bs, err := ioutil.ReadAll(response0.Body)
	if err != nil {
		return &GitHubToken{}, err
	}

	values, err = url.ParseQuery(string(bs))
	if err != nil {
		return &GitHubToken{}, err
	}

	accessToken := values.Get("access_token")

	client2 := urlfetch.Client(ctx)
	response, err := client2.Get("https://api.github.com/user/emails?access_token=" + accessToken)
	if err != nil {
		return &GitHubToken{}, err
	}
	defer response.Body.Close()

	var data []GitHubToken
	
	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return &GitHubToken{}, err
	}
	if len(data) == 0 {
		return &GitHubToken{}, fmt.Errorf("no email found")
	}
	return &data[0], nil
}

func GITHUB_Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := make(url.Values)
	values.Add("client_id",clientID)
	values.Add("redirect_uri",redirect)
	values.Add("scope", "user:email")
	values.Add("state", req.FormValue("redirect"))	
	http.Redirect(res, req, fmt.Sprintf("https://github.com/login/oauth/authorize?%s",values.Encode()), 302)
}