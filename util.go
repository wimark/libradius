package libradius

import (
	"encoding/binary"
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type AVPType uint8

const (
	VendorCisco  uint32 = 9
	VendorWimark uint32 = 15400
	VendorAlu    uint32 = 6527
	VendorRdp    uint32 = 250
)

const (
	WimarkAVPTypeClientStr      AVPType = 3
	WimarkAVPTypeSessionInt     AVPType = 4
	WimarkAVPTypeAlwaysRedirect AVPType = 5

	WimarkAVPTypeExternalAuthUserRole     AVPType = 6
	WimarkAVPTypeExternalAuthUserLocation AVPType = 7
)

const (
	CiscoAVPTypeDefault     AVPType = 1
	CiscoAVPTypeAccountInfo AVPType = 250
	CiscoAVPTypeCommandCode AVPType = 252

	CiscoAVPTypeExternalAuthUserRole     AVPType = 8
	CiscoAVPTypeExternalAuthUserLocation AVPType = 9
)

const (
	RdpServiceName AVPType = 250
)

const (
	CiscoCodeLogon  byte = 0x1
	CiscoCodeLogoff byte = 0x2
)

const (
	CiscoSubscriberLogon      string = "subscriber:command=account-logon"
	CiscoSubscriberLogoff     string = "subscriber:command=account-logoff"
	CiscoSubscriberReauth     string = "subscriber:command=reauthenticate"
	CiscoSubscriberReauthType string = "subscriber:reathenticate-type=last"
	CiscoAuditSessionID       string = "audit-session-id="
)

type AVP struct {
	VendorId uint32
	TypeId   uint8
	ValueLen uint8
	Value    []byte
}

func (a *AVP) String() string {
	return fmt.Sprintf("Vendor: %d, Type: %d, Value: %s", a.VendorId, a.TypeId, string(a.Value))
}

type WimarkAVPairs struct {
	ClientStr  string
	SessionInt int
}

type CiscoAVPairs struct {
	AccountInfo      string
	CommandCodeStr   string
	AuditSessionID   string
	CommandCodeBytes []byte
	AVPList          []string
}

func DecodeAVPair(vsa []byte) (*AVP, error) {
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

func DecodeAVPairs(p *radius.Packet, vendorID uint32) ([]*AVP, error) {
	var AVPItem *AVP
	var AVPList []*AVP
	var err error

	for _, vsa := range p.Attributes[rfc2865.VendorSpecific_Type] {
		if AVPItem, err = DecodeAVPair(radius.Bytes(vsa)); err != nil {
			return nil, err
		}

		if vendorID != 0 {
			if AVPItem.VendorId == vendorID {
				AVPList = append(AVPList, AVPItem)
			}
		} else {
			AVPList = append(AVPList, AVPItem)
		}
	}

	return AVPList, nil
}

func DecodeWimarkAVPairsStruct(p *radius.Packet) (*WimarkAVPairs, error) {
	var WimarkAVPairsList *WimarkAVPairs

	AVPList, err := DecodeAVPairs(p, VendorWimark)
	if err != nil {
		return nil, err
	}

	for _, AVPItem := range AVPList {
		if AVPItem.TypeId == uint8(WimarkAVPTypeClientStr) {
			WimarkAVPairsList.ClientStr = string(AVPItem.Value)
		}
	}

	return WimarkAVPairsList, nil
}

func DecodeCiscoAVPairsStruct(p *radius.Packet) (*CiscoAVPairs, error) {
	var CiscoAVPairsList *CiscoAVPairs

	AVPList, err := DecodeAVPairs(p, VendorCisco)
	if err != nil {
		return nil, err
	}

	for _, AVPItem := range AVPList {
		if AVPItem.TypeId == uint8(CiscoAVPTypeAccountInfo) {
			CiscoAVPairsList.AccountInfo = string(AVPItem.Value)
		}
		if AVPItem.TypeId == uint8(CiscoAVPTypeCommandCode) {
			CiscoAVPairsList.CommandCodeStr = string(AVPItem.Value)
			CiscoAVPairsList.CommandCodeBytes = AVPItem.Value
		}
		if AVPItem.TypeId == uint8(CiscoAVPTypeDefault) {
			CiscoAVPairsList.AVPList = append(CiscoAVPairsList.AVPList, string(AVPItem.Value))
		}
	}

	return CiscoAVPairsList, nil
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
