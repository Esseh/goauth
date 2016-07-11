package goauth
import(
	"net/http"
	"fmt"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"	
	"strings"
	"google.golang.org/appengine"
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


//////////////////////////////////////////////////////////////////////////////////
// Send for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
func googleSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(req,redirect,clientID)
	values.Add("scope", "openid email")
	http.Redirect(res, req, fmt.Sprintf("https://accounts.google.com/o/oauth2/auth?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Google OAuth
//////////////////////////////////////////////////////////////////////////////////
// An internal struct for a step of the google OAuth process.
type googleData struct {
	AccessToken string `json:"access_token"`
	IDToken		string `json:"id_token"`
	ExpiresIn   int64 `json:"expires_in"`
	TokenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}
func googleRecieve(req *http.Request, redirect ,clientID, secretID string, token *GoogleToken) error {
	ctx := appengine.NewContext(req)
	res, err := requiredRecieve(req, clientID, secretID, redirect, "https://www.googleapis.com/oauth2/v4/token")
	if err != nil { 
		log.Errorf(ctx,"Problem Generating Response\n\n",err)
		return err 
	}
	var data googleData
	err = extractValue(res, &data) 
	if err != nil { return err }
	
	client := urlfetch.Client(ctx)
	res2, err := client.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+data.AccessToken)
	if err != nil { return err }	

	var trueToken GoogleToken
	err = extractValue(res2, &trueToken) 
	if err != nil { return err }
	
	*token = trueToken
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}