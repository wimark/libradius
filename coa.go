package libradius

import (
	"fmt"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

type CoaRequest struct {
	FramedIPAddress string
	AcctSessionID   string
	SessionTimeout  int
	IdleTimeout     int
	VSAList         []VSAEntity
}

type VSAEntity struct {
	Vendor      uint32
	Attr        byte
	ValueString string
	ValueInt    int
}

func SendCoA(addr, secret string, request CoaRequest) error {
	packet := radius.New(radius.CodeCoARequest, []byte(""))
	packet.Secret = []byte(secret)
	rfc2865.FramedIPAddress_Add(packet, net.ParseIP(request.FramedIPAddress))
	rfc2866.AcctSessionID_AddString(packet, request.AcctSessionID)
	rfc2869.EventTimestamp_Add(packet, time.Now())
	rfc2865.IdleTimeout_Add(packet, rfc2865.IdleTimeout(request.IdleTimeout))
	rfc2865.SessionTimeout_Add(packet, rfc2865.SessionTimeout(request.SessionTimeout))

	for _, vsa := range request.VSAList {
		if len(vsa.ValueString) > 0 {
			AddVSAString(packet, vsa.Vendor, vsa.Attr, vsa.ValueString)
		} else {
			AddVSAInt(packet, vsa.Vendor, vsa.Attr, vsa.ValueInt)
		}
	}

	response, err := SendPacket(addr, packet)
	if err != nil {
		return err
	}

	if response != nil && response.Code != radius.CodeCoAACK {
		return fmt.Errorf("response is not CodeCoAACK: %d", response.Code)
	}

	return nil
}
