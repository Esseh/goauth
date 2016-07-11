package goauth
import(
	"net/http"
	"strings"
	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
)

type DropboxToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	UID         string `json:"uid"`
	State		string
}

//////////////////////////////////////////////////////////////////////////////////
// Send for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func dropboxSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(req,redirect,clientID)
	http.Redirect(res, req, "https://www.dropbox.com/1/oauth2/authorize?"+values.Encode(), http.StatusSeeOther)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func dropboxRecieve(req *http.Request, redirect ,clientID, secretID string, token *DropboxToken) error {
	values := requiredSend(req,redirect,clientID)
	ctx := appengine.NewContext(req)
	resp, err := urlfetch.Client(ctx).Get("https://www.dropbox.com/1/oauth2/authorize?"+values.Encode())
	if err != nil { return err }
	req = resp.Request
	
	res, err := requiredRecieve(req,clientID,secretID,redirect,"https://api.dropbox.com/1/oauth2/token") 
	if err != nil { return err }
	var data DropboxToken
	err = extractValue(res,&data)
	if err != nil { return err }
	*token = data
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}	