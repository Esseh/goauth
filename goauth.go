// goauth
/// blackboxed OAuth interactions.
package goauth
import(
	"net/http"
	"errors"
)

// ClientType helps goauth know how to generate http clients and resolve cross site checks. 
// In an init() it should be set to the type of application you're using ie:
//	"appengine"
// If a type is not specified it will attempt to create a base http.Client
// and use a cookie SHA scheme to resolve cross site checks.
// A special value is "override" which will override the behaviors with 3 
// functions "ClientOverride" , "CrossSiteInitialize", "CrossSiteResolve"
type Settings struct {
	ClientType string
	ClientOverride func(*http.Request)(*http.Client)
	CrossSiteInitializeOverride func(http.ResponseWriter,*http.Request,string)
	CrossSiteResolveOverride func(http.ResponseWriter,*http.Request) error
}

var GlobalSettings Settings
func init(){ 
	GlobalSettings = Settings{} 
}

var(
	// ErrBadToken is given if the type assertion in a recieve fails.
	ErrBadToken = errors.New("Token Error: Invalid Token Used. \nDid you remember to pass it in as a pointer?")
	// ErrCrossSite is given if states are invalid between send/recieve.
	ErrCrossSite= errors.New("Error: Terminate Request, Cross Site Attack Detected")
	// ErrNoData is given if 1 or more pieces of data were expected and 0 were recieved.
	ErrNoData = errors.New("Error: No Data Found")
)