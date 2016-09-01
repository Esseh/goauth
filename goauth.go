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
// ClientType helps goauth know how to generate http clients and resolve cross site checks. 
// In an init() it should be set to the type of application you're using ie:
//	"appengine"
// If a type is not specified it will attempt to create a base http.Client
// and use a cookie SHA scheme to resolve cross site checks.
// A special value is "override" which will override the behaviors with 3 
// functions "ClientOverride" , "CrossSiteInitialize", "CrossSiteResolve"
//////////////////////////////////////////////////////////////////////////////////
var ClientType string
// Creates the client for the application.
var ClientOverride func(*http.Request)(*http.Client)
// Initialize cross site checking. It should somehow store
// a piece of unique information.
var CrossSiteInitializeOverride func(http.ResponseWriter,*http.Request,string)
// Resolve cross site checking. It should ensure that the value
// stored in CrossSiteInitialize has not changed.
// If an error is returned it should return "goauth.ErrCrossSite"
var CrossSiteResolveOverride func(http.ResponseWriter,*http.Request) error

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