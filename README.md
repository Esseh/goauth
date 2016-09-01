# goauth
Black-boxed Golang API Management

*goauth is deprecated*
goauth is no longer meant to be used directly, the goauth package itself is a  blackboxed API manager meant to build API intefaces.
The functionality will be preserved in their own respective packages.

ie: instead of using a "github.com/Esseh/goauth".GoogleToken a "github.com/Esseh/goauth-google".Token will be used instead.
In practice the namespaces in this example will typically be..
goauth.GoogleToken and google.Token respectively.
