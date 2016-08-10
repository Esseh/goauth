package goauth
import(
	"net/http"
	"net/url"
	"fmt"
	"strings"
)

type GitHubToken struct {
	AccessToken string `json:"access_token"`
	Scope		string `json:"scope"`
	TokenType	string `json:"token_type"`
	State		string
}

func (d GitHubToken)Email(req *http.Request)(GitHubEmail , error){
	ai := []GitHubEmail{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://api.github.com/user/emails", values, &ai)	
	return ai[0],err
}
	
type GitHubEmail struct {
	Email    string
	Verified bool
	Primary  bool
}



//////////////////////////////////////////////////////////////////////////////////
// Send for Github OAuth
//////////////////////////////////////////////////////////////////////////////////	
func githubSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(res,req,redirect,clientID)
	http.Redirect(res, req, fmt.Sprintf("https://github.com/login/oauth/authorize?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Github OAuth
/// Github isn't taking my Accept: application/json
/// So Without the ability to unmarshal this ends up way uglier than it should 
/// be.
//////////////////////////////////////////////////////////////////////////////////	
func githubRecieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token *GitHubToken) error {
	resp, err := requiredRecieve(res,req,clientID,secretID,redirect,"https://github.com/login/oauth/access_token") 
	if err != nil { return err }

	err = extractValue(resp,token)
	if err != nil { return err }
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}

/*func githubRecieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token *GitHubToken) error {
	resp, err := requiredRecieve(res,req,clientID,secretID,redirect,"https://github.com/login/oauth/access_token") 
	if err != nil { return err }

	var ghd githubData
	err = extractValue(resp,&ghd)
	if err != nil { return err }
	
	// Make second request.
	response, err := internalClient(req).Get("https://api.github.com/user/emails?access_token=" + ghd.AccessToken)
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
}*/