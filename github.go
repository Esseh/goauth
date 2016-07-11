package goauth
import(
	"net/http"
	"fmt"
	"strings"
	"google.golang.org/appengine/urlfetch"	
	"google.golang.org/appengine"
)

type GitHubToken struct {
	Email    string
	Verified bool
	Primary  bool
	State 	 string
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
// Recieve for Github OAuth
/// Github isn't taking my Accept: application/json
/// So Without the ability to unmarshal this ends up way uglier than it should 
/// be.
//////////////////////////////////////////////////////////////////////////////////	
type githubData struct {
	AccessToken string `json:"access_token"`
	Scope		string `json:"scope"`
	TokenType	string `json:"token_type"`
}
func githubRecieve(req *http.Request, redirect ,clientID, secretID string, token *GitHubToken) error {
	res, err := requiredRecieve(req,clientID,secretID,redirect,"https://github.com/login/oauth/access_token") 
	if err != nil { return err }

	var ghd githubData
	err = extractValue(res,&ghd)
	if err != nil { return err }
	
	// Make second request.
	response, err := urlfetch.Client(appengine.NewContext(req)).Get("https://api.github.com/user/emails?access_token=" + ghd.AccessToken)
	if err != nil { return err }

	// Extract token. Make sure there is data.
	var data []GitHubToken
	err = extractValue(response,&data)
	if err != nil { return err }	
	if len(data) == 0 { return ErrNoData }

	// Attatch data and state.
	*token = data[0]
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}