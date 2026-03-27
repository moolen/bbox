package bbox

type ProxyOptions struct {
	NetworkPolicy NetworkPolicy
}

type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
}

type ProxyManager struct {
	policy *compiledPolicy
}
