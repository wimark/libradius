package libradius

import (
	"strconv"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	_Wimark_VendorID = 52400
)

func _Wimark_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	var vsa radius.Attribute
	vendor := make(radius.Attribute, 2+len(attr))
	vendor[0] = typ
	vendor[1] = byte(len(vendor))
	copy(vendor[2:], attr)
	vsa, err = radius.NewVendorSpecific(_Wimark_VendorID, vendor)
	if err != nil {
		return
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return
}

func _Wimark_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		attr := avp.Attribute
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Wimark_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				values = append(values, vsa[2:int(vsaLen)])
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _Wimark_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		attr := avp.Attribute
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Wimark_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				return vsa[2:int(vsaLen)], true
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _Wimark_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	for i := 0; i < len(p.Attributes); {
		avp := p.Attributes[i]
		if avp.Type != rfc2865.VendorSpecific_Type {
			i++
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != _Wimark_VendorID {
			i++
			continue
		}
		for j := 0; len(vsa[j:]) >= 3; {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {
				i++
				break
			}
			if vsaTyp == typ {
				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)
			}
			j += int(vsaLen)
		}
		if len(vsa) > 0 {
			copy(avp.Attribute[4:], vsa)
			i++
		} else {
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
		}
	}
	return _Wimark_AddVendor(p, typ, attr)
}

func _Wimark_DelVendor(p *radius.Packet, typ byte) {
vsaLoop:
	for i := 0; i < len(p.Attributes); {
		avp := p.Attributes[i]
		if avp.Type != rfc2865.VendorSpecific_Type {
			i++
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != _Wimark_VendorID {
			i++
			continue
		}
		offset := 0
		for len(vsa[offset:]) >= 3 {
			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				continue vsaLoop
			}
			if vsaTyp == typ {
				copy(vsa[offset:], vsa[offset+int(vsaLen):])
				vsa = vsa[:len(vsa)-int(vsaLen)]
			} else {
				offset += int(vsaLen)
			}
		}
		if offset == 0 {
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
		} else {
			i++
		}
	}
	return
}

func WimarkClientGroup_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 3, a)
}

func WimarkClientGroup_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 3, a)
}

func WimarkClientGroup_Get(p *radius.Packet) (value []byte) {
	value, _ = WimarkClientGroup_Lookup(p)
	return
}

func WimarkClientGroup_GetString(p *radius.Packet) (value string) {
	value, _ = WimarkClientGroup_LookupString(p)
	return
}

func WimarkClientGroup_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Wimark_GetsVendor(p, 3) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkClientGroup_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Wimark_GetsVendor(p, 3) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkClientGroup_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Wimark_LookupVendor(p, 3)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WimarkClientGroup_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Wimark_LookupVendor(p, 3)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WimarkClientGroup_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 3, a)
}

func WimarkClientGroup_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 3, a)
}

func WimarkClientGroup_Del(p *radius.Packet) {
	_Wimark_DelVendor(p, 3)
}

type WimarkSessionTimeout uint32

var WimarkSessionTimeout_Strings = map[WimarkSessionTimeout]string{}

func (a WimarkSessionTimeout) String() string {
	if str, ok := WimarkSessionTimeout_Strings[a]; ok {
		return str
	}
	return "WimarkSessionTimeout(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WimarkSessionTimeout_Add(p *radius.Packet, value WimarkSessionTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Wimark_AddVendor(p, 4, a)
}

func WimarkSessionTimeout_Get(p *radius.Packet) (value WimarkSessionTimeout) {
	value, _ = WimarkSessionTimeout_Lookup(p)
	return
}

func WimarkSessionTimeout_Gets(p *radius.Packet) (values []WimarkSessionTimeout, err error) {
	var i uint32
	for _, attr := range _Wimark_GetsVendor(p, 4) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WimarkSessionTimeout(i))
	}
	return
}

func WimarkSessionTimeout_Lookup(p *radius.Packet) (value WimarkSessionTimeout, err error) {
	a, ok := _Wimark_LookupVendor(p, 4)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WimarkSessionTimeout(i)
	return
}

func WimarkSessionTimeout_Set(p *radius.Packet, value WimarkSessionTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Wimark_SetVendor(p, 4, a)
}

func WimarkSessionTimeout_Del(p *radius.Packet) {
	_Wimark_DelVendor(p, 4)
}

type WimarkAlwaysRedirect uint32

var WimarkAlwaysRedirect_Strings = map[WimarkAlwaysRedirect]string{}

func (a WimarkAlwaysRedirect) String() string {
	if str, ok := WimarkAlwaysRedirect_Strings[a]; ok {
		return str
	}
	return "WimarkAlwaysRedirect(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WimarkAlwaysRedirect_Add(p *radius.Packet, value WimarkAlwaysRedirect) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Wimark_AddVendor(p, 5, a)
}

func WimarkAlwaysRedirect_Get(p *radius.Packet) (value WimarkAlwaysRedirect) {
	value, _ = WimarkAlwaysRedirect_Lookup(p)
	return
}

func WimarkAlwaysRedirect_Gets(p *radius.Packet) (values []WimarkAlwaysRedirect, err error) {
	var i uint32
	for _, attr := range _Wimark_GetsVendor(p, 5) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WimarkAlwaysRedirect(i))
	}
	return
}

func WimarkAlwaysRedirect_Lookup(p *radius.Packet) (value WimarkAlwaysRedirect, err error) {
	a, ok := _Wimark_LookupVendor(p, 5)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WimarkAlwaysRedirect(i)
	return
}

func WimarkAlwaysRedirect_Set(p *radius.Packet, value WimarkAlwaysRedirect) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Wimark_SetVendor(p, 5, a)
}

func WimarkAlwaysRedirect_Del(p *radius.Packet) {
	_Wimark_DelVendor(p, 5)
}

func WimarkWLANID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 8, a)
}

func WimarkWLANID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 8, a)
}

func WimarkWLANID_Get(p *radius.Packet) (value []byte) {
	value, _ = WimarkWLANID_Lookup(p)
	return
}

func WimarkWLANID_GetString(p *radius.Packet) (value string) {
	value, _ = WimarkWLANID_LookupString(p)
	return
}

func WimarkWLANID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Wimark_GetsVendor(p, 8) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkWLANID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Wimark_GetsVendor(p, 8) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkWLANID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Wimark_LookupVendor(p, 8)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WimarkWLANID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Wimark_LookupVendor(p, 8)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WimarkWLANID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 8, a)
}

func WimarkWLANID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 8, a)
}

func WimarkWLANID_Del(p *radius.Packet) {
	_Wimark_DelVendor(p, 8)
}

func WimarkCPEID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 9, a)
}

func WimarkCPEID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_AddVendor(p, 9, a)
}

func WimarkCPEID_Get(p *radius.Packet) (value []byte) {
	value, _ = WimarkCPEID_Lookup(p)
	return
}

func WimarkCPEID_GetString(p *radius.Packet) (value string) {
	value, _ = WimarkCPEID_LookupString(p)
	return
}

func WimarkCPEID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Wimark_GetsVendor(p, 9) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkCPEID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Wimark_GetsVendor(p, 9) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WimarkCPEID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Wimark_LookupVendor(p, 9)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WimarkCPEID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Wimark_LookupVendor(p, 9)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WimarkCPEID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 9, a)
}

func WimarkCPEID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Wimark_SetVendor(p, 9, a)
}

func WimarkCPEID_Del(p *radius.Packet) {
	_Wimark_DelVendor(p, 9)
}
