package libradius

import (
	"encoding/binary"
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type AVP struct {
	VendorId uint32
	TypeId   uint8
	ValueLen uint8
	Value    []byte
}

type WimarkAVPs struct {
	ClientStr  string
	SessionInt int
}

type CiscoAVPs struct {
	AccountInfo      string
	CommandCodeStr   string
	AuditSessionID   string
	CommandCodeBytes []byte
	AVPList          []string
}

func (a *AVP) String() string {
	return fmt.Sprintf("Vendor: %d, Type: %d, Value: %s", a.VendorId, a.TypeId, string(a.Value))
}

func DecodeAVPairVSA(vsa []byte) (*AVP, error) {
	if len(vsa) <= 6 {
		return nil, fmt.Errorf("too short VSA: %d bytes", len(vsa))
	}

	return &AVP{
		VendorId: binary.BigEndian.Uint32(vsa[0:4]),
		TypeId:   vsa[4],
		ValueLen: vsa[5],
		Value:    vsa[6:],
	}, nil
}

func DecodeAVPairsVSA(p *radius.Packet) ([]*AVP, error) {
	var AVPItem *AVP
	var AVPList []*AVP
	var err error

	for _, attr := range p.Attributes {
		if attr.Type != rfc2865.VendorSpecific_Type {
			AVPList = nil
			continue
		}

		AVPItem, err = DecodeAVPairVSA(radius.Bytes(attr.Attribute))
		if err != nil {
			AVPList = nil
			return nil, err
		} else {
			AVPList = append(AVPList, AVPItem)
		}
	}

	return AVPList, nil
}

func DecodeAVPairsVSAByVendor(p *radius.Packet, vendorID uint32) ([]*AVP, error) {
	var AVPItem *AVP
	var AVPList []*AVP
	var err error

	for _, attr := range p.Attributes {
		if attr.Type != rfc2865.VendorSpecific_Type {
			AVPList = nil
			continue
		}

		AVPItem, err = DecodeAVPairVSA(radius.Bytes(attr.Attribute))
		if err != nil {
			AVPList = nil
			return nil, err
		} else {
			if AVPItem.VendorId == vendorID {
				AVPList = append(AVPList, AVPItem)
			}
		}
	}

	return AVPList, nil
}

func DecodeWimarkAVPairsStruct(p *radius.Packet) (*WimarkAVPs, error) {
	var WimarkAVPStruct *WimarkAVPs
	AVPList, err := DecodeAVPairsVSAByVendor(p, VendorWimark)

	if err != nil {
		return nil, err
	}

	if AVPList == nil {
		return nil, fmt.Errorf("avps is empty")
	}

	for _, AVPItem := range AVPList {
		if AVPItem.TypeId == uint8(WimarkAVPTypeClientStr) {
			WimarkAVPStruct.ClientStr = string(AVPItem.Value)
		}
	}

	return WimarkAVPStruct, nil
}

func DecodeCiscoAVPairsStruct(p *radius.Packet) (*CiscoAVPs, error) {
	var CiscoAVPStruct *CiscoAVPs
	AVPList, err := DecodeAVPairsVSAByVendor(p, VendorCisco)

	if err != nil {
		return nil, err
	}

	if AVPList == nil {
		return nil, fmt.Errorf("avps is empty")
	}

	for _, AVPItem := range AVPList {
		if AVPItem.TypeId == uint8(CiscoAVPTypeAccountInfo) {
			CiscoAVPStruct.AccountInfo = string(AVPItem.Value)
		}
		if AVPItem.TypeId == uint8(CiscoAVPTypeCommandCode) {
			CiscoAVPStruct.CommandCodeStr = string(AVPItem.Value)
			CiscoAVPStruct.CommandCodeBytes = AVPItem.Value
		}
		if AVPItem.TypeId == uint8(CiscoAVPTypeDefault) {
			CiscoAVPStruct.AVPList = append(CiscoAVPStruct.AVPList, string(AVPItem.Value))
		}
	}

	return CiscoAVPStruct, nil
}

func AddVSAString(p *radius.Packet, vendor uint32, attribute uint8, value string) {
	bytes, _ := radius.NewBytes([]byte(value))
	attr := make(radius.Attribute, 2+len(bytes))
	attr[0] = attribute
	attr[1] = byte(len(attr))
	copy(attr[2:], bytes)
	vsa, _ := radius.NewVendorSpecific(vendor, attr)
	p.Add(rfc2865.VendorSpecific_Type, vsa)
}

func AddVSAInt(p *radius.Packet, vendor uint32, attribute uint8, value int) {
	bytes := radius.NewInteger(uint32(value))
	attr := make(radius.Attribute, 2+len(bytes))
	attr[0] = attribute
	attr[1] = byte(len(attr))
	copy(attr[2:], bytes)
	vsa, _ := radius.NewVendorSpecific(vendor, attr)
	p.Add(rfc2865.VendorSpecific_Type, vsa)
}

func CreateHexVSAByWlanID(value string) (hex []byte) {
	if len(value) > 249 {
		return
	}
	bytes := []byte(value)
	attr := make([]byte, 2+len(bytes))
	attr[0], attr[1] = byte(WimarkIdentifierWLANType), byte(len(attr))
	copy(attr[2:], bytes)
	hex = make([]byte, 4+len(attr))
	binary.BigEndian.PutUint32(hex, VendorWimark)
	copy(hex[4:], attr)
	return
}
