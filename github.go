package goauth
import(
	"time"
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

func (d GitHubToken)AccountInfo(req *http.Request)(GitHubAccountInfo , error){
	ai := []GitHubAccountInfo{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://api.github.com/user", values, &ai)	
	return ai[0],err
}
	
type GitHubEmail struct {
	Email    string `json:"email"`
	Verified   bool `json:"verified"`
	Primary    bool `json:"primary"`
}

type GitHubAccountInfo struct {
	Login string `json:"login"`
	ID int `json:"id"`
	AvatarURL string `json:"avatar_url"`
	GravatarID string `json:"gravatar_id"`
	URL string `json:"url"`
	HTMLURL string `json:"html_url"`
	FollowersURL string `json:"followers_url"`
	FollowingURL string `json:"following_url"`
	GistsURL string `json:"gists_url"`
	StarredURL string `json:"starred_url"`
	SubscriptionsURL string `json:"subscriptions_url"`
	OrganizationsURL string `json:"organizations_url"`
	ReposURL string `json:"repos_url"`
	EventsURL string `json:"events_url"`
	ReceivedEventsURL string `json:"received_events_url"`
	Type string `json:"type"`
	SiteAdmin bool `json:"site_admin"`
	Name interface{} `json:"name"`
	Company interface{} `json:"company"`
	Blog interface{} `json:"blog"`
	Location interface{} `json:"location"`
	Email interface{} `json:"email"`
	Hireable interface{} `json:"hireable"`
	Bio interface{} `json:"bio"`
	PublicRepos int `json:"public_repos"`
	PublicGists int `json:"public_gists"`
	Followers int `json:"followers"`
	Following int `json:"following"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
