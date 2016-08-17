package goauth
import(
	"net/url"
	"encoding/json"
	"github.com/nu7hatch/gouuid"
	"net/http"
	"strings"
)

//////////////////////////////////////////////////////////////////////////////////
// Required Parameters - Also performs first half of check against cross-site attacks
//////////////////////////////////////////////////////////////////////////////////
func RequiredSend(res http.ResponseWriter,req *http.Request,redirect, clientID string) url.Values {
	values := make(url.Values)
	values.Add("client_id",clientID)
	values.Add("redirect_uri",redirect)
	values.Add("response_type","code")

	id , _ := uuid.NewV4()
	values.Add("state", id.String() + "](|)[" + req.FormValue("state"))

	v := values.Get("state")
	CrossSiteInitialize(res,req, v)
	
	return values
}


//////////////////////////////////////////////////////////////////////////////////
// Makes the required recieve request for an access token.
// ASSUMES: I am getting JSON back.
// I can add in an Accept: application/json
// but I have only used that for Github which ignored it.
//////////////////////////////////////////////////////////////////////////////////
func RequiredRecieve(res http.ResponseWriter, req *http.Request, clientID, secretID, redirect, src string) (*http.Response, error) {
	values := make(url.Values)
	
	intErr := CrossSiteResolve(res,req)
	if intErr != nil { return &http.Response{},ErrCrossSite }
	
	values.Add("code", req.FormValue("code"))
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", secretID)
	values.Add("redirect_uri", redirect)	

	client := InternalClient(req)
	reqq, err := http.NewRequest("POST", src, strings.NewReader(values.Encode()))
	if err != nil { 
		return &http.Response{}, err 
	}
	reqq.Header.Set("Accept","application/json")
	return client.Do(reqq)
}

//////////////////////////////////////////////////////////////////////////////////
// Uses reflection to extract a JSON object from a response into an input struct.
//////////////////////////////////////////////////////////////////////////////////
func ExtractValue(res *http.Response, data interface{}) error {
	defer res.Body.Close()
	err := json.NewDecoder(res.Body).Decode(data)
	if err != nil {
		return err
	}
	return nil 
}

//////////////////////////////////////////////////////////////////////////////////
// Multiplexer to determine the proper way to generate an http.Client{}
//////////////////////////////////////////////////////////////////////////////////
func InternalClient(req *http.Request) *http.Client{
	switch ClientType{
		case "override":
			return ClientOverride(req)
		case "appengine":
			return AppengineClient(req)
	}
	return &http.Client{}
}



func CallAPI(req *http.Request,METHOD, src string, values url.Values, data interface{}) error {
	client := InternalClient(req)
	var reqq *http.Request
	var err error
	if METHOD == "POST" {
		reqq, err = http.NewRequest(METHOD, src, strings.NewReader(values.Encode()))
	} else {
		reqq, err = http.NewRequest(METHOD, src+"?"+values.Encode(), nil)
	}

	if err != nil { return err }
	reqq.Header.Set("Accept","application/json")
	resp, err := client.Do(reqq)	
	if err != nil { return err }
	return ExtractValue(resp,&data)
}