package libradius

import (
	"fmt"

	"layeh.com/radius"
)

type RadiusServerConfig struct {
	Host   string
	Port   string
	Secret string
}

func NewRadiusServerConfig(host, port, secret string) *RadiusServerConfig {
	return &RadiusServerConfig{
		Host:   host,
		Port:   port,
		Secret: secret,
	}
}

func (c *RadiusServerConfig) GetAddr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

func ServerRun(cfg *RadiusServerConfig, handler func(w radius.ResponseWriter, r *radius.Request)) error {
	server := radius.PacketServer{
		Addr:         cfg.GetAddr(),
		SecretSource: radius.StaticSecretSource([]byte(cfg.Secret)),
		Handler:      radius.HandlerFunc(handler),
	}

	return server.ListenAndServe()
}

func ServerRunAsync(cfg *RadiusServerConfig, h func(w radius.ResponseWriter, r *radius.Request)) (*radius.PacketServer, error) {
	server := radius.PacketServer{
		Addr:         cfg.GetAddr(),
		SecretSource: radius.StaticSecretSource([]byte(cfg.Secret)),
		Handler:      radius.HandlerFunc(h),
	}

	go server.ListenAndServe()

	return &server, nil
}
