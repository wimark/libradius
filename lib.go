package libradius

import (
	"context"
	// "fmt"
	"time"

	radius "layeh.com/radius"
)

const (
	RADIUS_START  = "Start"
	RADIUS_UPDATE = "Interim-Update"
	RADIUS_STOP   = "Stop"
)

const (
	RADIUS_NAS_PORT_TYPE_WIFI = "wireless"
	RADIUS_NAS_PORT_TYPE_ETH  = "ethernet"
)

const (
	RADIUS_CAUSE_STOP  = "Host-Request"
	RADIUS_CAUSE_SESS  = "Session-Timeout"
	RADIUS_CAUSE_ADMIN = "Admin-Reset"
)

type RadiusServer struct {
	Host string
	Port int
}

func ServerRun(addr string, secret string,
	f func(w radius.ResponseWriter,
		r *radius.Request)) {

	server := radius.PacketServer{
		Addr:         addr,
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler:      radius.HandlerFunc(f),
	}

	server.ListenAndServe()
}

// func for make radius exchange and return rsp packet
func SendPacket(addr string, packet *radius.Packet) (*radius.Packet, error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	rcv, err := radius.Exchange(ctx, packet, addr)
	if err != nil {
		return nil, err
	}

	return rcv, nil
}

// func for reliably (almost) send radius packet
func SendPacketReliably(rs []string, packet *radius.Packet) (*radius.Packet, error) {
	var err error
	var rcv *radius.Packet
	for _, v := range rs {
		rcv, err = SendPacket(v, packet)
		if err == nil {
			return rcv, nil
		}
	}
	return rcv, err
}
