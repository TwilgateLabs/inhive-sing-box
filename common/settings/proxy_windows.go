package settings

import (
	"context"
	"net/url"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/wininet"
)

type WindowsSystemProxy struct {
	serverAddr   M.Socksaddr
	supportSOCKS bool
	user         string
	pass         string
	isEnabled    bool
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool, user, pass string) (*WindowsSystemProxy, error) {
	return &WindowsSystemProxy{
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
		user:         user,
		pass:         pass,
	}, nil
}

func (p *WindowsSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *WindowsSystemProxy) Enable() error {
	var proxyURL string
	if p.user != "" && p.pass != "" {
		// Include credentials so browsers don't show an auth prompt.
		u := &url.URL{
			Scheme: "http",
			User:   url.UserPassword(p.user, p.pass),
			Host:   p.serverAddr.String(),
		}
		proxyURL = u.String()
	} else {
		proxyURL = "http://" + p.serverAddr.String()
	}
	err := wininet.SetSystemProxy(proxyURL, "")
	if err != nil {
		return err
	}
	p.isEnabled = true
	return nil
}

func (p *WindowsSystemProxy) Disable() error {
	err := wininet.ClearSystemProxy()
	if err != nil {
		return err
	}
	p.isEnabled = false
	return nil
}
