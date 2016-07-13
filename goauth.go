//////////////////////////////////////////////////////////////////////////////////
// goauth
/// blackboxed OAuth interactions.
//////////////////////////////////////////////////////////////////////////////////
package goauth
import(
	"net/http"
	"errors"
)

//////////////////////////////////////////////////////////////////////////////////
// ClientType helps goauth know how to generate http clients. In an init() it should
// be set to the type of application you're using ie:
//	"appengine"
// If a type is not specified it will attempt to create a base http.Client
//////////////////////////////////////////////////////////////////////////////////
var ClientType string

var(
	//////////////////////////////////////////////////////////////////////////////////
	// ErrBadToken is given if the type assertion in a recieve fails.
	//////////////////////////////////////////////////////////////////////////////////
	ErrBadToken = errors.New("Token Error: Invalid Token Used. \nDid you remember to pass it in as a pointer?")
	//////////////////////////////////////////////////////////////////////////////////
	// ErrCrossSite is given if states are invalid between send/recieve.
	//////////////////////////////////////////////////////////////////////////////////
	ErrCrossSite= errors.New("Error: Terminate Request, Cross Site Attack Detected")
	//////////////////////////////////////////////////////////////////////////////////
	// ErrNoData is given if 1 or more pieces of data were expected and 0 were recieved.
	//////////////////////////////////////////////////////////////////////////////////
	ErrNoData = errors.New("Error: No Data Found")
)

//////////////////////////////////////////////////////////////////////////////////
// Send if a multiplexer function that based on the token type will choose
// the correct function to execute for the first step of the OAuth handshake.
//////////////////////////////////////////////////////////////////////////////////
func Send(res http.ResponseWriter, req *http.Request, redirect ,clientID string, model interface{}){
	switch model.(type){
		case *DropboxToken:
			dropboxSend(res, req, redirect, clientID)
		case *GitHubToken:
			githubSend(res, req, redirect, clientID)
		case *GoogleToken:
			googleSend(res, req, redirect, clientID)
	}
}

//////////////////////////////////////////////////////////////////////////////////
// Recieve is a multiplexer function, based on the token type it will use the 
// appropriate function to get the OAuth token.
//////////////////////////////////////////////////////////////////////////////////
func Recieve(res http.ResponseWriter, req *http.Request, redirect ,clientID, secretID string, token interface{}) error {
	switch token.(type){
		case *DropboxToken:
			return dropboxRecieve(res, req, redirect ,clientID, secretID, token.(*DropboxToken))
		case *GitHubToken:
			return githubRecieve(res, req, redirect ,clientID, secretID, token.(*GitHubToken))
		case *GoogleToken:
			return googleRecieve(res, req, redirect ,clientID, secretID, token.(*GoogleToken))
	}
	return ErrBadToken
}