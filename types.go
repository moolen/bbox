package bbox

type ProxyOptions struct{}

type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
}

type ProxyManager struct{}
