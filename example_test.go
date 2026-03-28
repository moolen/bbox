package bbox_test

import (
	"fmt"
	"log"

	"github.com/moolen/bbox"
)

func ExampleNewProxyManager() {
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		ListenAddr: "127.0.0.1:0",
		NetworkPolicy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	fmt.Println("manager ready")
	// Output: manager ready
}

func ExampleProxyOptions() {
	opts := bbox.ProxyOptions{
		ListenAddr: "127.0.0.1:0",
		NetworkPolicy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^api[.]github[.]com$`, `^github[.]com$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	}

	fmt.Println(opts.ListenAddr)
	fmt.Println(opts.NetworkPolicy.AllowConnect)
	// Output:
	// 127.0.0.1:0
	// true
}
