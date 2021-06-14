package libradius 

import (
	"time"
	"fmt"
	"net"

	radius "layeh.com/radius"
	. "layeh.com/radius/rfc2865"
	. "layeh.com/radius/rfc2866"
	. "layeh.com/radius/rfc2869"
)

type CoaRequest struct {
	FramedIPAddress string 
	AcctSessionID string 
	SessionTimeout int 
	IdleTimeout int 
	VSA []VSAEntity 
}

type VSAEntity struct {
	Vendor uint32
	Attr byte 
	ValueString string 
	ValueInt int 
}

func SendCoA(host string, port int, secret string, request CoaRequest) error {
	packet := radius.New(radius.CodeCoARequest, []byte(""))
	packet.Secret = []byte(secret)

	FramedIPAddress_Add(packet, net.ParseIP(request.FramedIPAddress))
	AcctSessionID_AddString(packet, request.AcctSessionID)
	EventTimestamp_Set(packet, time.Now())
	IdleTimeout_Add(packet, IdleTimeout(request.IdleTimeout))
	SessionTimeout_Add(packet, SessionTimeout(request.SessionTimeout))

	for _, v:= range request.VSA {
		if len(v.ValueString) > 0 {
			AddVSAString(packet, v.Vendor, v.Attr, v.ValueString)
		} else {
			AddVSAInt(packet, v.Vendor, v.Attr, v.ValueInt)
		}
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	rcv, err := SendPacket(addr, packet)
	if err != nil {
		return err 
	}

	if rcv != nil && rcv.Code != radius.CodeCoAACK {
		return fmt.Errorf("Got not CodeCoAck: %d", rcv.Code)
	}

	return nil
}