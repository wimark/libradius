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

// struct for RADIUS AVP
type AVP struct {
	VendorId uint32
	TypeId   uint8
	Value    []byte
	ValueInt uint32
}

func (avp *AVP) String() string {
	return fmt.Sprintf("Vendor: %d, Type: %d, Value: %s, ValueInt: %d", avp.VendorId,
		avp.TypeId, string(avp.Value), avp.ValueInt)
}

type WimarkAVPs struct {
	ClientGroup    string
	SessionTimeout int
}

type CiscoAVPs struct {
	AccountInfo string
	CommandCode string
	AVPs        []string
}

// Decodes VSA (byte)
func DecodeAVPairByte(vsa []byte) (vendor_id uint32, type_id uint8, value []byte, value_int uint32, err error) {
	if len(vsa) <= 6 {
		err = fmt.Errorf("Too short VSA: %d bytes", len(vsa))
		return
	}

	vendor_id = binary.BigEndian.Uint32([]byte{vsa[0], vsa[1], vsa[2], vsa[3]})
	type_id = uint8(vsa[4])
	value = vsa[5:]
	value_int = binary.BigEndian.Uint32(value)
	return
}

// Decodes All AVPs from radius.Packet
func DecodeAVPairs(p *radius.Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		Value    []byte
		ValueInt uint32
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, Value, ValueInt, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			avps = append(avps,
				&AVP{
					VendorId: VendorId,
					TypeId:   TypeId,
					Value:    Value,
					ValueInt: ValueInt,
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
		Value    []byte
		ValueInt uint32
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, Value, ValueInt, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			if VendorId == VEND_WIMARK {
				avps = append(avps,
					&AVP{
						VendorId: VendorId,
						TypeId:   TypeId,
						Value:    Value,
						ValueInt: ValueInt,
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
			avpst.SessionTimeout = int(avp.ValueInt)
		}
	}
	return
}

// Decodes only Cisco VSA AVPs from radius.Packet
func DecodeCiscoAVPairs(p *radius.Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		Value    []byte
		ValueInt uint32
	)

	for _, vsa := range p.Attributes[VendorSpecific_Type] {
		if VendorId, TypeId, Value, ValueInt, err = DecodeAVPairByte(radius.Bytes(vsa)); err != nil {
			avps = nil
			return
		} else {
			if VendorId == VEND_CISCO {
				avps = append(avps,
					&AVP{
						VendorId: VendorId,
						TypeId:   TypeId,
						Value:    Value,
						ValueInt: ValueInt,
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
			avpst.CommandCode = string(avp.Value)
		}
		if avp.TypeId == uint8(CiscoAVPTypeDefault) {
			avpst.AVPs = append(avpst.AVPs, string(avp.Value))
		}
	}
	return
}
