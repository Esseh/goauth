package goauth
import(
	"net/http"
	"strings"
	"net/url"
)

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
func dropboxSend(res http.ResponseWriter, req *http.Request, redirect ,clientID string){
	values := requiredSend(res,req,redirect,clientID)
	http.Redirect(res, req, "https://www.dropbox.com/1/oauth2/authorize?"+values.Encode(), http.StatusSeeOther)
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve for Dropbox OAuth
//////////////////////////////////////////////////////////////////////////////////
func dropboxRecieve(res http.ResponseWriter,req *http.Request, redirect ,clientID, secretID string, token *DropboxToken) error {
	resp, err := requiredRecieve(res,req,clientID,secretID,redirect,"https://api.dropbox.com/1/oauth2/token") 
	if err != nil { return err }
	var data DropboxToken
	err = extractValue(resp,&data)
	if err != nil { return err }
	*token = data
	token.State = strings.Split(req.FormValue("state"),"](|)[")[1]
	return nil
}	