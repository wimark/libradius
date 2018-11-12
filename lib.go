package libradius

import (
	"context"
	"fmt"
	"time"

	radius "layeh.com/radius"
)

type AcctSessionType = string
type AuthSessionType = string

const (
	AcctSessionTypeStart   AcctSessionType = "start"
	AcctSessionTypeInterim AcctSessionType = "interim"
	AcctSessionTypeStop    AcctSessionType = "stop"

	AuthSessionTypeNone    AuthSessionType = "none"
	AuthSessionTypeRequest AuthSessionType = "request"
	AuthSessionTypeAccept  AuthSessionType = "accept"
	AuthSessionTypeReject  AuthSessionType = "reject"
)

func ServerRun(host string, port int, secret string,
	f func(w radius.ResponseWriter,
		r *radius.Request)) {

	server := radius.PacketServer{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler:      radius.HandlerFunc(f),
	}

	server.ListenAndServe()
}

// func for make radius exchange and return rsp packet
func SendPacket(host string, port int, packet *radius.Packet) (*radius.Packet, error) {

	hostport := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	rcv, err := radius.Exchange(ctx, packet, hostport)
	if err != nil {
		return nil, err
	}

	return rcv, nil
}
