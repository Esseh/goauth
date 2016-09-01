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
	ai := GitHubAccountInfo{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://api.github.com/user", values, &ai)	
	return ai,err
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
func GithubSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := RequiredSend(res,req,redirect,clientID)
	http.Redirect(res, req, fmt.Sprintf("https://github.com/login/oauth/authorize?%s",values.Encode()), 302)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Github OAuth
/// Github isn't taking my Accept: application/json
/// So Without the ability to unmarshal this ends up way uglier than it should 
/// be.
//////////////////////////////////////////////////////////////////////////////////	
func GithubRecieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token *GitHubToken) error {
	resp, err := RequiredRecieve(res,req,clientID,secretID,redirect,"https://github.com/login/oauth/access_token") 
	if err != nil { return err }

	err = ExtractValue(resp,token)
	if err != nil { return err }
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}

type DropboxToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	UID         string `json:"uid"`
	State		string
}

type DropboxAccountInfo struct {
	UID int `json:"uid"`
	DisplayName string `json:"display_name"`
	NameDetails struct {
		FamiliarName string `json:"familiar_name"`
		GivenName string `json:"given_name"`
		Surname string `json:"surname"`
	} `json:"name_details"`
	ReferralLink string `json:"referral_link"`
	Country string `json:"country"`
	Locale string `json:"locale"`
	Email string `json:"email"`
	EmailVerified bool `json:"email_verified"`
	IsPaired bool `json:"is_paired"`
	Team struct {
		Name string `json:"name"`
		TeamID string `json:"team_id"`
	} `json:"team"`
	QuotaInfo struct {
		Shared int64 `json:"shared"`
		Quota int64 `json:"quota"`
		Normal int64 `json:"normal"`
	} `json:"quota_info"`
}

func (d DropboxToken)AccountInfo(req *http.Request)(DropboxAccountInfo , error){
	ai := DropboxAccountInfo{}
	values := make(url.Values)
	values.Add("access_token",d.AccessToken)
	err := CallAPI(req,"GET", "https://api.dropboxapi.com/1/account/info", values, &ai)	
	return ai,err
}

//////////////////////////////////////////////////////////////////////////////////
// Send for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func DropboxSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := RequiredSend(res,req,redirect,clientID)
	http.Redirect(res, req, "https://www.dropbox.com/1/oauth2/authorize?"+values.Encode(), http.StatusSeeOther)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func DropboxRecieve(res http.ResponseWriter,req *http.Request, redirect ,clientID, secretID string, token *DropboxToken) error {
	resp, err := RequiredRecieve(res,req,clientID,secretID,redirect,"https://api.dropbox.com/1/oauth2/token") 
	if err != nil { return err }
	
	var data DropboxToken
	err = ExtractValue(resp,&data)
	if err != nil { return err }
	*token = data
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}	

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

//////////////////////////////////////////////////////////////////////////////////
// Send if a multiplexer function that based on the token type will choose
// the correct function to execute for the first step of the OAuth handshake.
//////////////////////////////////////////////////////////////////////////////////
func Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string, model interface{}){
	switch model.(type){
		case *DropboxToken:
			DropboxSend(res, req, redirect, clientID)
		case *GitHubToken:
			GithubSend(res, req, redirect, clientID)
		case *GoogleToken:
			GoogleSend(res, req, redirect, clientID)
	}
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve is a multiplexer function, based on the token type it will use the 
// appropriate function to get the OAuth token.
//////////////////////////////////////////////////////////////////////////////////
func Recieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token interface{}) error {
	switch token.(type){
		case *DropboxToken:
			return DropboxRecieve(res, req, redirect ,clientID, secretID, token.(*DropboxToken))
		case *GitHubToken:
			return GithubRecieve(res, req, redirect ,clientID, secretID, token.(*GitHubToken))
		case *GoogleToken:
			return GoogleRecieve(res, req, redirect ,clientID, secretID, token.(*GoogleToken))
	}
	return ErrBadToken
}