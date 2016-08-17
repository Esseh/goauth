package goauth
import(
	"net/http"
	"net/url"
	"fmt"
	"strings"
)
type GoogleToken struct {
	AccessToken string `json:"access_token"`
	IDToken		string `json:"id_token"`
	ExpiresIn   int64 `json:"expires_in"`
	TokenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	State string
}

func (d GoogleToken)TokenInfo(req *http.Request)(GoogleTokenInfo , error){
	ai := GoogleTokenInfo{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://www.googleapis.com/oauth2/v3/tokeninfo", values, &ai)	
	return ai,err
}

func (d GoogleToken)AccountInfo(req *http.Request)(GoogleAccountInfo , error){
	ai := GoogleAccountInfo{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://www.googleapis.com/oauth2/v3/userinfo", values, &ai)	
	return ai,err
}

type GoogleTokenInfo struct {
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

type GoogleAccountInfo struct {
	Sub				string `json:"sub"`
	FullName		string `json:"name"`
	FirstName		string `json:"given_name"`
	LastName		string `json:"family_name"`
	ProfileURL		string `json:"profile"`
	PictureURL		string `json:"picture"`
	Email			string `json:"email"`
	EmailVerified 	  bool `json:"email_verified"`
	Gender 			string `json:"gender"`
}
//////////////////////////////////////////////////////////////////////////////////
// Send for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
func GoogleSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := RequiredSend(res,req,redirect,clientID)
	values.Add("scope", "openid email")
	http.Redirect(res, req, fmt.Sprintf("https://accounts.google.com/o/oauth2/auth?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
func GoogleRecieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token *GoogleToken) error {
	resp, err := RequiredRecieve(res,req, clientID, secretID, redirect, "https://www.googleapis.com/oauth2/v4/token")
	if err != nil { 
		return err 
	}
	err = ExtractValue(resp,token) 
	if err != nil { return err }

	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}