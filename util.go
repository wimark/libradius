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
	VEND_RDP    = 250 
)

type AVPType uint8

const (
	WimarkAVPTypeClientstr    AVPType = 3
	WimarkAVPTypeSessionint AVPType = 4
	WimarkAVPTypeAlwaysRedirect AVPType = 5
)

const (
	CiscoAVPTypeDefault     AVPType = 1
	CiscoAVPTypeAccountInfo AVPType = 250
	CiscoAVPTypeCommandCode AVPType = 252
)

const (
	RdpServiceName AVPType = 250
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
	Clientstr    string
	Sessionint int
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
		if avp.TypeId == uint8(WimarkAVPTypeClientstr) {
			avpst.Clientstr = string(avp.Value)
		}
		if avp.TypeId == uint8(WimarkAVPTypeSessionint) {
			// avpst.Sessionint = int(avp.ValueInt)
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

func AddVSAString(p *radius.Packet, vendor uint32, attribute uint8, value string) {
	rbytes, _ := radius.NewBytes([]byte(value))
	attr := make(radius.Attribute, 2+len(rbytes))
	attr[0] = byte(attribute)
	attr[1] = byte(len(attr))
	copy(attr[2:], rbytes)
	vsa, _ := radius.NewVendorSpecific(vendor, attr) 
	p.Add(VendorSpecific_Type, vsa)
}

func AddVSAInt(p *radius.Packet, vendor uint32, attribute uint8, value int) {
	rbytes := radius.NewInteger(uint32(value))
	attr := make(radius.Attribute, 2+len(rbytes))
	attr[0] = byte(attribute)
	attr[1] = byte(len(attr))
	copy(attr[2:], rbytes)
	vsa, _ := radius.NewVendorSpecific(vendor, attr) 
	p.Add(VendorSpecific_Type, vsa)
}


