package goauth
import(
	"time"
	"net/http"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"	
)
//////////////////////////////////////////////////////////////////////////////////
// Generates appengine client
//////////////////////////////////////////////////////////////////////////////////
func appengineClient(req *http.Request)*http.Client{
	return urlfetch.Client(appengine.NewContext(req))
}

//////////////////////////////////////////////////////////////////////////////////
// Uses memcache to hold unique value.
//////////////////////////////////////////////////////////////////////////////////
func appengineCrossSiteInitialize(res http.ResponseWriter,req *http.Request, v string){
	memcache.Set(appengine.NewContext(req), &memcache.Item{
		Key: v,
		Value: []byte("s"),
		Expiration: time.Duration(time.Minute),
	})			
}

//////////////////////////////////////////////////////////////////////////////////
// Checks unique value in memcache
//////////////////////////////////////////////////////////////////////////////////
func appengineCrossSiteResolve(res http.ResponseWriter,req *http.Request) error {
	ctx := appengine.NewContext(req)
	_ , memErr := memcache.Get(ctx, req.FormValue("state"))
	if memErr != nil { return ErrCrossSite }
	return nil
}