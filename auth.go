package libradius

import (
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type RadiusUserData struct {
	UserRole     string
	UserLocation string
}

type RadiusAuth struct {
	IsActive      bool                 `json:"is_active"`
	Protocol      string               `json:"protocol"`
	RadiusServers []RadiusServerConfig `json:"radius_servers"`
}

func (a *RadiusAuth) Validate() error {
	if a.Protocol != "PAP" {
		return fmt.Errorf("incorrect protocol for external radius auth")
	}

	if len(a.RadiusServers) <= 0 {
		return fmt.Errorf("incorrect length of radius servers list")
	}

	return nil
}

func LookupExternalRadiusAuthAttrs(p *radius.Packet) (*RadiusUserData, error) {
	var data RadiusUserData
	if len(p.Attributes) == 0 {
		return nil, fmt.Errorf("attributes list from response RADIUS packet is empty")
	}

	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}

		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil {
			continue
		}

		if vendorID == VendorWimark {
			for len(vsa) >= 3 {
				vsaType, vsaLen := vsa[0], vsa[1]
				if int(vsaLen) > len(vsa) || vsaLen < 3 {
					break
				}

				if vsaType == byte(WimarkRadiusExternalAuthUserRoleType) {
					data.UserRole = radius.String(vsa[2:int(vsaLen)])
				}

				if vsaType == byte(WimarkRadiusExternalAuthUserLocationType) {
					data.UserLocation = radius.String(vsa[2:int(vsaLen)])
				}

				vsa = vsa[int(vsaLen):]
			}
		}
	}

	if len(data.UserRole) == 0 {
		err := fmt.Errorf("attribute UserRole not found")
		return nil, err
	}

	if len(data.UserLocation) == 0 {
		err := fmt.Errorf("attribute UserLocation not found")
		return nil, err
	}

	return &data, nil
}
