package libradius

import (
	"context"
	"time"

	"layeh.com/radius"
)

type RadiusClientConfig struct {
	MaxPacketErrors int
	Retry           time.Duration
}

func NewRadiusClientConfig(maxPacketErrors int, retry time.Duration) *RadiusClientConfig {
	return &RadiusClientConfig{
		MaxPacketErrors: maxPacketErrors,
		Retry:           retry,
	}
}

func NewRadiusClient(cfg *RadiusClientConfig) *radius.Client {
	return &radius.Client{
		Retry:           cfg.Retry,
		MaxPacketErrors: cfg.MaxPacketErrors,
	}
}

func SendPacket(addr string, packet *radius.Packet) (*radius.Packet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSendRadiusPacketTimeout)
	defer cancel()

	response, err := radius.Exchange(ctx, packet, addr)
	if err != nil {
		return nil, err
	}

	return response, nil
}
