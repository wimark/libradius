package libradius

import (
	"encoding/binary"
	"fmt"

	radius "layeh.com/radius"
	. "layeh.com/radius/rfc2865"
)

const (
	VEND_CISCO  = 9
	VEND_WIMARK = 15400
	VEND_ALU    = 6527
)

type AVPType uint8

const (
	WimarkAVPTypeClientGroup    AVPType = 3
	WimarkAVPTypeSessionTimeout AVPType = 4
	WimarkAVPTypeAlwaysRedirect AVPType = 5
)

const (
	CiscoAVPTypeDefault     AVPType = 1
	CiscoAVPTypeAccountInfo AVPType = 250
	CiscoAVPTypeCommandCode AVPType = 252
)

const (
	CiscoCodeLogon  = byte(0x1)
	CiscoCodeLogoff = byte(0x2)
)

const (
	CiscoSubscriberLogon      = "subscriber:command=account-logon"
	CiscoSubscriberLogoff     = "subscriber:command=account-logoff"
	CiscoSubscriberReauth     = "subscriber:command=reauthenticate"
	CiscoSubscriberReauthType = "subsriber:reathenticate-type=last"
	CiscoAuditSessionID       = "audit-session-id="
)

// struct for RADIUS AVP
type AVP struct {
	VendorId uint32
	TypeId   uint8
	ValueLen uint8
	Value    []byte
}

func (avp *AVP) String() string {
	return fmt.Sprintf("Vendor: %d, Type: %d, Value: %s", avp.VendorId,
		avp.TypeId, string(avp.Value))
}

type WimarkAVPs struct {
	ClientGroup    string
	SessionTimeout int
}

type CiscoAVPs struct {
	AccountInfo      string
	CommandCodeStr   string
	CommandCodeBytes []byte
	AuditSessionID   string
	AVPs             []string
}

// Decodes VSA (byte)
func DecodeAVPairByte(vsa []byte) (vendor_id uint32, type_id uint8, length uint8, value []byte, err error) {
	if len(vsa) <= 6 {
		err = fmt.Errorf("Too short VSA: %d bytes", len(vsa))
		return
	}

	vendor_id = binary.BigEndian.Uint32(vsa[0:4])
	type_id = uint8(vsa[4])
	length = uint8(vsa[5])
	value = vsa[6:]
	return
}

// Decodes All AVPs from radius.Packet
func DecodeAVPairs(p *radius.Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		ValueLen uint8
		Value    []byte
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, ValueLen, Value, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			avps = append(avps,
				&AVP{
					VendorId: VendorId,
					TypeId:   TypeId,
					ValueLen: ValueLen,
					Value:    Value,
				},
			)
		}
	}

	return
}

// Decodes only Wimark VSA AVPs from radius.Packet
func DecodeWimarkAVPairs(p *radius.Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		ValueLen uint8
		Value    []byte
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, ValueLen, Value, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			if VendorId == VEND_WIMARK {
				avps = append(avps,
					&AVP{
						VendorId: VendorId,
						TypeId:   TypeId,
						ValueLen: ValueLen,
						Value:    Value,
					},
				)
			}
		}
	}

	return
}

func DecodeWimarkAVPairsStruct(p *radius.Packet) (avpst WimarkAVPs, err error) {
	avps, err := DecodeWimarkAVPairs(p)

	if avps == nil {
		return
	}

	for _, avp := range avps {
		if avp.TypeId == uint8(WimarkAVPTypeClientGroup) {
			avpst.ClientGroup = string(avp.Value)
		}
		if avp.TypeId == uint8(WimarkAVPTypeSessionTimeout) {
			// avpst.SessionTimeout = int(avp.ValueInt)
		}
	}
	return
}

// Decodes only Cisco VSA AVPs from radius.Packet
func DecodeCiscoAVPairs(p *radius.Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		ValueLen uint8
		Value    []byte
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, ValueLen, Value, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			if VendorId == VEND_CISCO {
				avps = append(avps,
					&AVP{
						VendorId: VendorId,
						TypeId:   TypeId,
						ValueLen: ValueLen,
						Value:    Value,
					},
				)
			}
		}
	}

	return
}

func DecodeCiscoAVPairsStruct(p *radius.Packet) (avpst CiscoAVPs, err error) {
	avps, err := DecodeCiscoAVPairs(p)

	if avps == nil {
		return
	}

	for _, avp := range avps {
		if avp.TypeId == uint8(CiscoAVPTypeAccountInfo) {
			avpst.AccountInfo = string(avp.Value)
		}
		if avp.TypeId == uint8(CiscoAVPTypeCommandCode) {
			avpst.CommandCodeStr = string(avp.Value)
			avpst.CommandCodeBytes = avp.Value
		}
		if avp.TypeId == uint8(CiscoAVPTypeDefault) {
			avpst.AVPs = append(avpst.AVPs, string(avp.Value))
		}
	}
	return
}
