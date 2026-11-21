package include

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/tun"
)

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), endpoint.NewRegistry(), DNSTransportRegistry(), ServiceRegistry(), certificate.NewRegistry())
}

func InboundRegistry() *inbound.Registry {
	r := inbound.NewRegistry()
	tun.RegisterInbound(r)
	redirect.RegisterRedirect(r)
	redirect.RegisterTProxy(r)
	direct.RegisterInbound(r)
	mixed.RegisterInbound(r)
	return r
}

func OutboundRegistry() *outbound.Registry {
	r := outbound.NewRegistry()
	direct.RegisterOutbound(r)
	block.RegisterOutbound(r)
	group.RegisterSelector(r)
	group.RegisterURLTest(r)
	vless.RegisterOutbound(r)
	hysteria2.RegisterOutbound(r)
	shadowsocks.RegisterOutbound(r)
	trojan.RegisterOutbound(r)
	vmess.RegisterOutbound(r)
	tuic.RegisterOutbound(r)
	anytls.RegisterOutbound(r)
	return r
}

func DNSTransportRegistry() *dns.TransportRegistry {
	r := dns.NewTransportRegistry()
	transport.RegisterTCP(r)
	transport.RegisterUDP(r)
	transport.RegisterTLS(r)
	transport.RegisterHTTPS(r)
	hosts.RegisterTransport(r)
	local.RegisterTransport(r)
	return r
}

func ServiceRegistry() *service.Registry {
	return service.NewRegistry()
}
