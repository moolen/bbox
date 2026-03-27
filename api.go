package bbox

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	policy, err := compilePolicy(opts.NetworkPolicy)
	if err != nil {
		return nil, err
	}
	return newProxyManager(policy), nil
}
