package libradius

import "time"

type AVPType uint8

const (
	VendorCisco    uint32 = 9
	VendorWimark   uint32 = 52400
	VendorAirspace uint32 = 14179
	VendorAlu      uint32 = 6527
	VendorRdp      uint32 = 250
)

const (
	RadiusStart  = "Start"
	RadiusUpdate = "Interim-Update"
	RadiusStop   = "Stop"
)

const (
	RadiusNASPortTypeWifi     = "wireless"
	RadiusNASPortTypeEthernet = "ethernet"
)

const (
	RadiusCauseStop    = "Host-Request"
	RadiusCauseSession = "Session-Timeout"
	RadiusCauseAdmin   = "Admin-Reset"
)

const (
	defaultSendRadiusPacketTimeout = time.Second * 5
)

const (
	WimarkAVPTypeClientStr                       AVPType = 3
	WimarkAVPTypeSessionInt                      AVPType = 4
	WimarkAVPTypeAlwaysRedirect                  AVPType = 5
	WimarkRadiusExternalAuthUserRoleType         AVPType = 6
	WimarkRadiusExternalAuthUserLocationType     AVPType = 7
	WimarkIdentifierWLANType                     AVPType = 8
	WimarkAuthCPEIDType                          AVPType = 9
	WimarkRadiusExternalAuthUserLocationNameType AVPType = 10
)

const (
	CiscoAVPTypeDefault     AVPType = 1
	CiscoAVPTypeAccountInfo AVPType = 250
	CiscoAVPTypeCommandCode AVPType = 252
)

const (
	AirspaceAVPTypeACLName AVPType = 6
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
	CiscoSubscriberReauthType = "subscriber:reathenticate-type=last"
	CiscoAuditSessionID       = "audit-session-id="
)
