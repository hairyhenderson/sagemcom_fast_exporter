package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// requestBody - represents the body of a request to the API
//
// note: order of fields is significant - the API will reject requests if the
// order is not maintained
//
//nolint:govet
type requestBody struct {
	ID        int      `json:"id"`
	SessionID int      `json:"session-id"`
	Priority  bool     `json:"priority"`
	Actions   []action `json:"actions"`
	Cnonce    int      `json:"cnonce"`
	AuthKey   string   `json:"auth-key"`
}

// action - represents a single action to be performed
//
// note: order of fields is significant - the API will reject requests if the
// order is not maintained
//
//nolint:govet
type action struct {
	ID         int            `json:"id"`
	Method     string         `json:"method"`
	Parameters map[string]any `json:"parameters,omitempty"`
	XPath      string         `json:"xpath,omitempty"`
}

type sessionOptions struct {
	Language                 string          `json:"language"`
	TimeFormat               string          `json:"time-format"`
	WriteOnlyString          string          `json:"write-only-string"`
	UndefinedWriteOnlyString string          `json:"undefined-write-only-string"`
	Nss                      []nss           `json:"nss"`
	CapabilityDepth          int             `json:"capability-depth"`
	ContextFlags             contextFlags    `json:"context-flags"`
	CapabilityFlags          capabilityFlags `json:"capability-flags"`
}

type nss struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type contextFlags struct {
	GetContentName bool `json:"get-content-name"`
	LocalTime      bool `json:"local-time"`
}

type capabilityFlags struct {
	Name         bool `json:"name"`
	DefaultValue bool `json:"default-value"`
	Restriction  bool `json:"restriction"`
	Description  bool `json:"description"`
}

type responseBody struct {
	Error   *xmoError     `json:"error"`
	Actions []actionResp  `json:"actions"`
	Events  []interface{} `json:"events"`
	UID     int           `json:"uid"`
	ID      int           `json:"id"`
}

type result struct {
	Description string `json:"description"`
	Code        int    `json:"code"`
}

type actionResp struct {
	Error     *xmoError      `json:"error"`
	Callbacks []callbackResp `json:"callbacks"`
	UID       int            `json:"uid"`
	ID        int            `json:"id"`
}

type callbackResp struct {
	Result     *result                    `json:"result"`
	Parameters map[string]json.RawMessage `json:"parameters"`
	XPath      string                     `json:"xpath"`
	UID        int                        `json:"uid"`
}

// error types
type xmoError struct {
	Description string
	Code        int
}

func (e *xmoError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Description, e.Code)
}

// Is - errors are equal if their descriptions are equal - codes are ignored
// for now
func (e *xmoError) Is(target error) bool {
	t, ok := target.(*xmoError)
	if !ok {
		return false
	}

	return e.Description == t.Description
}

var (
	ErrRequestNoError    = &xmoError{Code: 16777216, Description: "XMO_REQUEST_NO_ERR"}
	ErrInvalidSession    = &xmoError{Code: 16777219, Description: "XMO_INVALID_SESSION_ERR"}
	ErrAuthentication    = &xmoError{Code: 16777223, Description: "XMO_AUTHENTICATION_ERR"}
	ErrRequestAction     = &xmoError{Code: 16777236, Description: "XMO_REQUEST_ACTION_ERR"}
	ErrNoError           = &xmoError{Code: 16777238, Description: "XMO_NO_ERR"}
	ErrAccessRestriction = &xmoError{Code: 1, Description: "XMO_ACCESS_RESTRICTION_ERR"}
	ErrNonWritableParam  = &xmoError{Code: 3, Description: "XMO_NON_WRITABLE_PARAMETER_ERR"}
	ErrUnknownPath       = &xmoError{Code: 7, Description: "XMO_UNKNOWN_PATH_ERR"}
	ErrMaxSessionCount   = &xmoError{Code: 8, Description: "XMO_MAX_SESSION_COUNT_ERR"}
)

type dhcpv4 struct {
	Server struct {
		Pools []struct {
			Alias             string `json:"Alias,omitempty"`
			BootFileName      string `json:"BootFileName,omitempty"`
			Chaddr            string `json:"Chaddr,omitempty"`
			ChaddrMask        string `json:"ChaddrMask,omitempty"`
			ClientID          string `json:"ClientID,omitempty"`
			DNSServers        string `json:"DNSServers,omitempty"`
			DomainName        string `json:"DomainName,omitempty"`
			IPInterface       string `json:"IPInterface,omitempty"`
			IPRouters         string `json:"IPRouters,omitempty"`
			Interface         string `json:"Interface,omitempty"`
			MaxAddress        string `json:"MaxAddress,omitempty"`
			MinAddress        string `json:"MinAddress,omitempty"`
			NextServer        string `json:"NextServer,omitempty"`
			ReservedAddresses string `json:"ReservedAddresses,omitempty"`
			ServerName        string `json:"ServerName,omitempty"`
			Status            string `json:"Status,omitempty"`
			SubnetMask        string `json:"SubnetMask,omitempty"`
			UserClassID       string `json:"UserClassID,omitempty"`
			VendorClassID     string `json:"VendorClassID,omitempty"`
			VendorClassIDMode string `json:"VendorClassIDMode,omitempty"`
			Clients           []struct {
				Alias         string `json:"Alias,omitempty"`
				Chaddr        string `json:"Chaddr,omitempty"`
				IPv4Addresses []struct {
					IPAddress          string `json:"IPAddress,omitempty"`
					LeaseTimeRemaining string `json:"LeaseTimeRemaining,omitempty"`
					UID                int    `json:"uid,omitempty"`
				} `json:"IPv4Addresses,omitempty"`
				Options []struct {
					Value string `json:"Value,omitempty"`
					Tag   int    `json:"Tag,omitempty"`
					UID   int    `json:"uid,omitempty"`
				} `json:"Options,omitempty"`
				UID    int  `json:"uid,omitempty"`
				Active bool `json:"Active,omitempty"`
			} `json:"Clients,omitempty"`
			Options []struct {
				Alias  string `json:"Alias,omitempty"`
				Value  string `json:"Value,omitempty"`
				Tag    int    `json:"Tag,omitempty"`
				UID    int    `json:"uid,omitempty"`
				Enable bool   `json:"Enable,omitempty"`
			} `json:"Options,omitempty"`
			StaticAddresses        []any `json:"StaticAddresses,omitempty"`
			LeaseTime              int   `json:"LeaseTime,omitempty"`
			Order                  int   `json:"Order,omitempty"`
			UID                    int   `json:"uid,omitempty"`
			AllowKnownClients      bool  `json:"AllowKnownClients,omitempty"`
			BlockAckFlag           bool  `json:"BlockAckFlag,omitempty"`
			ChaddrExclude          bool  `json:"ChaddrExclude,omitempty"`
			ClientIDExclude        bool  `json:"ClientIDExclude,omitempty"`
			DHCPServerConfigurable bool  `json:"DHCPServerConfigurable,omitempty"`
			Enable                 bool  `json:"Enable,omitempty"`
			FlushDHCPLeases        bool  `json:"FlushDHCPLeases,omitempty"`
			UserClassIDExclude     bool  `json:"UserClassIDExclude,omitempty"`
			VendorClassIDExclude   bool  `json:"VendorClassIDExclude,omitempty"`
			XSAGEMCOMForceOptions  bool  `json:"X_SAGEMCOM_ForceOptions,omitempty"`
		} `json:"Pools,omitempty"`
		XmoConfVersion         int  `json:"XmoConfVersion,omitempty"`
		XSAGEMCOMAuthoritative bool `json:"X_SAGEMCOM_Authoritative,omitempty"`
		Enable                 bool `json:"Enable,omitempty"`
	} `json:"Server,omitempty"`
}

type dns struct {
	SupportedRecordTypes string `json:"SupportedRecordTypes,omitempty"`
	Sd                   struct {
		Services []any `json:"Services,omitempty"`
		Enable   bool  `json:"Enable,omitempty"`
	} `json:"SD,omitempty"`
	Client struct {
		HostName     string `json:"HostName,omitempty"`
		LocalDomains string `json:"LocalDomains,omitempty"`
		Status       string `json:"Status,omitempty"`
		Servers      []struct {
			Alias      string `json:"Alias,omitempty"`
			DNSServer  string `json:"DNSServer,omitempty"`
			Interface  string `json:"Interface,omitempty"`
			Status     string `json:"Status,omitempty"`
			Type       string `json:"Type,omitempty"`
			StaticDNSs []any  `json:"StaticDNSs,omitempty"`
			UID        int    `json:"uid,omitempty"`
			Enable     bool   `json:"Enable,omitempty"`
		} `json:"Servers,omitempty"`
		Attempts          int  `json:"Attempts,omitempty"`
		FallbackTimeout   int  `json:"FallbackTimeout,omitempty"`
		Enable            bool `json:"Enable,omitempty"`
		GenerateHostsFile bool `json:"GenerateHostsFile,omitempty"`
		UseGUAAddress     bool `json:"UseGUAAddress,omitempty"`
		UseLLAAddress     bool `json:"UseLLAAddress,omitempty"`
		UseULAAddress     bool `json:"UseULAAddress,omitempty"`
	} `json:"Client,omitempty"`
	Diagnostics struct {
		NSLookupDiagnostics struct {
			DNSServer           string `json:"DNSServer,omitempty"`
			DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
			HostName            string `json:"HostName,omitempty"`
			Interface           string `json:"Interface,omitempty"`
			Results             []any  `json:"Results,omitempty"`
			NumberOfRepetitions int    `json:"NumberOfRepetitions,omitempty"`
			SuccessCount        int    `json:"SuccessCount,omitempty"`
			Timeout             int    `json:"Timeout,omitempty"`
		} `json:"NSLookupDiagnostics,omitempty"`
	} `json:"Diagnostics,omitempty"`
	Relay struct {
		Forwardings []struct {
			Alias      string `json:"Alias,omitempty"`
			DNSServer  string `json:"DNSServer,omitempty"`
			Interface  string `json:"Interface,omitempty"`
			Status     string `json:"Status,omitempty"`
			Type       string `json:"Type,omitempty"`
			StaticDNSs []any  `json:"StaticDNSs,omitempty"`
			UID        int    `json:"uid,omitempty"`
			Enable     bool   `json:"Enable,omitempty"`
		} `json:"Forwardings,omitempty"`
		InputInterfaces []struct {
			Interface   string `json:"Interface,omitempty"`
			UID         int    `json:"uid,omitempty"`
			AcceptInput bool   `json:"AcceptInput,omitempty"`
		} `json:"InputInterfaces,omitempty"`
		AllowedRebindingDomains string `json:"AllowedRebindingDomains,omitempty"`
		NoForwardDomains        string `json:"NoForwardDomains,omitempty"`
		Status                  string `json:"Status,omitempty"`
		Cache                   struct {
			Content                string `json:"Content,omitempty"`
			QueriesPerServers      string `json:"QueriesPerServers,omitempty"`
			Status                 string `json:"Status,omitempty"`
			UsageStatistics        string `json:"UsageStatistics,omitempty"`
			AvailableMemory        int    `json:"AvailableMemory,omitempty"`
			QueriesAnsweredLocally int    `json:"QueriesAnsweredLocally,omitempty"`
			QueriesForwarded       int    `json:"QueriesForwarded,omitempty"`
			FlushCache             bool   `json:"FlushCache,omitempty"`
		} `json:"Cache,omitempty"`
		Attempts                        int  `json:"Attempts,omitempty"`
		CacheSize                       int  `json:"CacheSize,omitempty"`
		FallbackTimeout                 int  `json:"FallbackTimeout,omitempty"`
		MaximumTTLServer                int  `json:"MaximumTTLServer,omitempty"`
		MinimumSourcePort               int  `json:"MinimumSourcePort,omitempty"`
		NegativeTTLServer               int  `json:"NegativeTTLServer,omitempty"`
		RetransmissionTimeout           int  `json:"RetransmissionTimeout,omitempty"`
		ServerQuarantineTimeout         int  `json:"ServerQuarantineTimeout,omitempty"`
		ServerQuarantineTimeoutEndRange int  `json:"ServerQuarantineTimeoutEndRange,omitempty"`
		Debug                           bool `json:"Debug,omitempty"`
		Enable                          bool `json:"Enable,omitempty"`
		HandleRetransmissions           bool `json:"HandleRetransmissions,omitempty"`
		StopDNSRebind                   bool `json:"StopDNSRebind,omitempty"`
		TryAllNsAfterNxDomain           bool `json:"TryAllNsAfterNxDomain,omitempty"`
	} `json:"Relay,omitempty"`
}

type ethernet struct {
	Links []struct {
		Alias       string `json:"Alias,omitempty"`
		IfcName     string `json:"IfcName,omitempty"`
		LowerLayers string `json:"LowerLayers,omitempty"`
		MACAddress  string `json:"MACAddress,omitempty"`
		Name        string `json:"Name,omitempty"`
		Status      string `json:"Status,omitempty"`
		StoppedBy   string `json:"StoppedBy,omitempty"`
		Stats       struct {
			BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
			BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
			BytesReceived               string `json:"BytesReceived,omitempty"`
			BytesSent                   string `json:"BytesSent,omitempty"`
			MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
			MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
			PacketsReceived             string `json:"PacketsReceived,omitempty"`
			PacketsSent                 string `json:"PacketsSent,omitempty"`
			UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
			UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
			CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
			DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
			DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
			ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
			ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
			RetransCount                int    `json:"RetransCount,omitempty"`
			UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
		} `json:"Stats,omitempty"`
		LastChange      int  `json:"LastChange,omitempty"`
		LastStatsReset  int  `json:"LastStatsReset,omitempty"`
		UID             int  `json:"uid,omitempty"`
		Enable          bool `json:"Enable,omitempty"`
		PriorityTagging bool `json:"PriorityTagging,omitempty"`
		ResetStats      bool `json:"ResetStats,omitempty"`
	} `json:"Links,omitempty"`
	RMONStatistics   []any               `json:"RMONStatistics,omitempty"`
	Interfaces       []EthernetInterface `json:"Interfaces,omitempty"`
	VLANTerminations []struct {
		Alias                   string `json:"Alias,omitempty"`
		EgressPriorityMappings  string `json:"EgressPriorityMappings,omitempty"`
		IfcName                 string `json:"IfcName,omitempty"`
		IngressPriorityMappings string `json:"IngressPriorityMappings,omitempty"`
		LowerLayers             string `json:"LowerLayers,omitempty"`
		Name                    string `json:"Name,omitempty"`
		Status                  string `json:"Status,omitempty"`
		StoppedBy               string `json:"StoppedBy,omitempty"`
		Stats                   struct {
			BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
			BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
			BytesReceived               string `json:"BytesReceived,omitempty"`
			BytesSent                   string `json:"BytesSent,omitempty"`
			MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
			MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
			PacketsReceived             string `json:"PacketsReceived,omitempty"`
			PacketsSent                 string `json:"PacketsSent,omitempty"`
			UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
			UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
			CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
			DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
			DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
			ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
			ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
			RetransCount                int    `json:"RetransCount,omitempty"`
			UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
		} `json:"Stats,omitempty"`
		LastChange     int  `json:"LastChange,omitempty"`
		LastStatsReset int  `json:"LastStatsReset,omitempty"`
		Tpid           int  `json:"TPID,omitempty"`
		Vlanid         int  `json:"VLANID,omitempty"`
		UID            int  `json:"uid,omitempty"`
		Enable         bool `json:"Enable,omitempty"`
		ResetStats     bool `json:"ResetStats,omitempty"`
		Untagged       bool `json:"Untagged,omitempty"`
	} `json:"VLANTerminations,omitempty"`
	OAM struct {
		OAM3ah struct {
			InterfaceName string `json:"InterfaceName,omitempty"`
			Features      int    `json:"features,omitempty"`
			Loopback      int    `json:"loopback,omitempty"`
			OamID         int    `json:"oamID,omitempty"`
			EnableOAM3Ah  bool   `json:"EnableOAM3ah,omitempty"`
		} `json:"OAM3ah,omitempty"`
		OAM1731 struct {
			InterfaceName string `json:"InterfaceName,omitempty"`
			CCMinterval   int    `json:"CCMinterval,omitempty"`
			Loopback      int    `json:"loopback,omitempty"`
			Meg           int    `json:"meg,omitempty"`
			MegLevel      int    `json:"megLevel,omitempty"`
			MepID         int    `json:"mepId,omitempty"`
			Vlan          int    `json:"vlan,omitempty"`
			EnableOAM1731 bool   `json:"EnableOAM1731,omitempty"`
			Ccm           bool   `json:"ccm,omitempty"`
		} `json:"OAM1731,omitempty"`
		OAM1ag struct {
			InterfaceName string `json:"InterfaceName,omitempty"`
			CCMinterval   int    `json:"CCMinterval,omitempty"`
			Loopback      int    `json:"loopback,omitempty"`
			Ma            int    `json:"ma,omitempty"`
			Md            int    `json:"md,omitempty"`
			MdLevel       int    `json:"mdLevel,omitempty"`
			MegLevel      int    `json:"megLevel,omitempty"`
			MepID         int    `json:"mepId,omitempty"`
			Vlan          int    `json:"vlan,omitempty"`
			EnableOAM1Ag  bool   `json:"EnableOAM1ag,omitempty"`
			Ccm           bool   `json:"ccm,omitempty"`
		} `json:"OAM1ag,omitempty"`
	} `json:"OAM,omitempty"`
}

type EthernetInterface struct {
	Alias             string               `json:"Alias,omitempty"`
	DuplexMode        string               `json:"DuplexMode,omitempty"`
	IfcName           string               `json:"IfcName,omitempty"`
	LowerLayers       string               `json:"LowerLayers,omitempty"`
	MACAddress        string               `json:"MACAddress,omitempty"`
	Name              string               `json:"Name,omitempty"`
	Role              string               `json:"Role,omitempty"`
	Status            string               `json:"Status,omitempty"`
	StoppedBy         string               `json:"StoppedBy,omitempty"`
	Diagnostics       InterfaceDiagnostics `json:"Diagnostics,omitempty"`
	AssociatedDevices []any                `json:"AssociatedDevices,omitempty"`
	CurrentBitRate    int64                `json:"CurrentBitRate,omitempty"`
	Stats             InterfaceStats       `json:"Stats,omitempty"`
	LastChange        int                  `json:"LastChange,omitempty"`
	LastStatsReset    int                  `json:"LastStatsReset,omitempty"`
	MTUSize           int                  `json:"MTUSize,omitempty"`
	MaxBitRate        int                  `json:"MaxBitRate,omitempty"`
	PhyNum            int                  `json:"PhyNum,omitempty"`
	UID               int                  `json:"uid,omitempty"`
	EEECapability     bool                 `json:"EEECapability,omitempty"`
	EEEEnable         bool                 `json:"EEEEnable,omitempty"`
	Enable            bool                 `json:"Enable,omitempty"`
	ResetStats        bool                 `json:"ResetStats,omitempty"`
	Upstream          bool                 `json:"Upstream,omitempty"`
}

type InterfaceDiagnostics struct {
	CableStatus       string `json:"CableStatus,omitempty"`
	CurrentDuplexMode string `json:"CurrentDuplexMode,omitempty"`
	CableLength       int    `json:"CableLength,omitempty"`
}

type InterfaceStats struct {
	BroadcastPacketsReceived    int64 `json:"BroadcastPacketsReceived,omitempty,string"`
	BroadcastPacketsSent        int64 `json:"BroadcastPacketsSent,omitempty,string"`
	BytesReceived               int64 `json:"BytesReceived,omitempty,string"`
	BytesSent                   int64 `json:"BytesSent,omitempty,string"`
	CollisionsPackets           int64 `json:"CollisionsPackets,omitempty"`
	DiscardPacketsReceived      int64 `json:"DiscardPacketsReceived,omitempty"`
	DiscardPacketsSent          int64 `json:"DiscardPacketsSent,omitempty"`
	ErrorsReceived              int64 `json:"ErrorsReceived,omitempty"`
	ErrorsSent                  int64 `json:"ErrorsSent,omitempty"`
	MulticastPacketsReceived    int64 `json:"MulticastPacketsReceived,omitempty,string"`
	MulticastPacketsSent        int64 `json:"MulticastPacketsSent,omitempty,string"`
	PacketsReceived             int64 `json:"PacketsReceived,omitempty,string"`
	PacketsSent                 int64 `json:"PacketsSent,omitempty,string"`
	RetransCount                int64 `json:"RetransCount,omitempty"`
	UnicastPacketsReceived      int64 `json:"UnicastPacketsReceived,omitempty,string"`
	UnicastPacketsSent          int64 `json:"UnicastPacketsSent,omitempty,string"`
	UnknownProtoPacketsReceived int64 `json:"UnknownProtoPacketsReceived,omitempty"`
}

type firewall struct {
	AdvancedLevel string `json:"AdvancedLevel,omitempty"`
	Config        string `json:"Config,omitempty"`
	LanInterface  string `json:"LanInterface,omitempty"`
	LastChange    string `json:"LastChange,omitempty"`
	Type          string `json:"Type,omitempty"`
	Version       string `json:"Version,omitempty"`
	Chains        []struct {
		Alias   string `json:"Alias,omitempty"`
		Creator string `json:"Creator,omitempty"`
		Name    string `json:"Name,omitempty"`
		Rules   []struct {
			Alias                  string `json:"Alias,omitempty"`
			CreationDate           string `json:"CreationDate,omitempty"`
			Creator                string `json:"Creator,omitempty"`
			Description            string `json:"Description,omitempty"`
			DestIP                 string `json:"DestIP,omitempty"`
			DestInterface          string `json:"DestInterface,omitempty"`
			DestMask               string `json:"DestMask,omitempty"`
			ExpiryDate             string `json:"ExpiryDate,omitempty"`
			MacID                  string `json:"MacId,omitempty"`
			Protocol               string `json:"Protocol,omitempty"`
			Service                string `json:"Service,omitempty"`
			SourceIP               string `json:"SourceIP,omitempty"`
			SourceInterface        string `json:"SourceInterface,omitempty"`
			SourceMask             string `json:"SourceMask,omitempty"`
			Status                 string `json:"Status,omitempty"`
			Target                 string `json:"Target,omitempty"`
			TargetChain            string `json:"TargetChain,omitempty"`
			Order                  int64  `json:"Order,omitempty"`
			Dscp                   int    `json:"DSCP,omitempty"`
			DestPort               int    `json:"DestPort,omitempty"`
			DestPortRangeMax       int    `json:"DestPortRangeMax,omitempty"`
			IPVersion              int    `json:"IPVersion,omitempty"`
			ProtocolNumber         int    `json:"ProtocolNumber,omitempty"`
			SourcePort             int    `json:"SourcePort,omitempty"`
			SourcePortRangeMax     int    `json:"SourcePortRangeMax,omitempty"`
			UID                    int    `json:"uid,omitempty"`
			DSCPExclude            bool   `json:"DSCPExclude,omitempty"`
			DestAllInterfaces      bool   `json:"DestAllInterfaces,omitempty"`
			DestIPExclude          bool   `json:"DestIPExclude,omitempty"`
			DestInterfaceExclude   bool   `json:"DestInterfaceExclude,omitempty"`
			DestPortExclude        bool   `json:"DestPortExclude,omitempty"`
			Enable                 bool   `json:"Enable,omitempty"`
			Log                    bool   `json:"Log,omitempty"`
			ProtocolExclude        bool   `json:"ProtocolExclude,omitempty"`
			SourceAllInterfaces    bool   `json:"SourceAllInterfaces,omitempty"`
			SourceIPExclude        bool   `json:"SourceIPExclude,omitempty"`
			SourceInterfaceExclude bool   `json:"SourceInterfaceExclude,omitempty"`
			SourcePortExclude      bool   `json:"SourcePortExclude,omitempty"`
		} `json:"Rules,omitempty"`
		UID    int  `json:"uid,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"Chains,omitempty"`
	Interfaces []struct {
		Interface              string `json:"Interface,omitempty"`
		IPv4IcmpFloodDetection int    `json:"IPv4IcmpFloodDetection,omitempty"`
		IPv4PortScanDetection  int    `json:"IPv4PortScanDetection,omitempty"`
		IPv4SynFloodDetection  int    `json:"IPv4SynFloodDetection,omitempty"`
		IPv4UDPFloodDetection  int    `json:"IPv4UdpFloodDetection,omitempty"`
		IPv6IcmpFloodDetection int    `json:"IPv6IcmpFloodDetection,omitempty"`
		IPv6PortScanDetection  int    `json:"IPv6PortScanDetection,omitempty"`
		IPv6SynFloodDetection  int    `json:"IPv6SynFloodDetection,omitempty"`
		IPv6UDPFloodDetection  int    `json:"IPv6UdpFloodDetection,omitempty"`
		UID                    int    `json:"uid,omitempty"`
		EnableIPSourceCheck    bool   `json:"EnableIpSourceCheck,omitempty"`
		RespondToPing4         bool   `json:"RespondToPing4,omitempty"`
		RespondToPing6         bool   `json:"RespondToPing6,omitempty"`
		SendPing4              bool   `json:"SendPing4,omitempty"`
		SendPing6              bool   `json:"SendPing6,omitempty"`
	} `json:"Interfaces,omitempty"`
	Levels []struct {
		Alias              string `json:"Alias,omitempty"`
		Chain              string `json:"Chain,omitempty"`
		DefaultPolicy      string `json:"DefaultPolicy,omitempty"`
		Description        string `json:"Description,omitempty"`
		Name               string `json:"Name,omitempty"`
		Order              int    `json:"Order,omitempty"`
		UID                int    `json:"uid,omitempty"`
		DefaultLogPolicy   bool   `json:"DefaultLogPolicy,omitempty"`
		PortMappingEnabled bool   `json:"PortMappingEnabled,omitempty"`
	} `json:"Levels,omitempty"`
	BlockFragmentedIPPackets bool `json:"BlockFragmentedIPPackets,omitempty"`
	PortScanDetection        bool `json:"PortScanDetection,omitempty"`
	Enable                   bool `json:"Enable,omitempty"`
}

type ip struct {
	IPv4Status  string `json:"IPv4Status,omitempty"`
	IPv6Status  string `json:"IPv6Status,omitempty"`
	ULAPrefix   string `json:"ULAPrefix,omitempty"`
	ActivePorts []any  `json:"ActivePorts,omitempty"`
	Interfaces  []struct {
		Alias         string `json:"Alias,omitempty"`
		IPv4Addresses []struct {
			AddressingType string `json:"AddressingType,omitempty"`
			Alias          string `json:"Alias,omitempty"`
			DNS            string `json:"Dns,omitempty"`
			IPAddress      string `json:"IPAddress,omitempty"`
			IPGateway      string `json:"IPGateway,omitempty"`
			Status         string `json:"Status,omitempty"`
			SubnetMask     string `json:"SubnetMask,omitempty"`
			UID            int    `json:"uid,omitempty"`
			Enable         bool   `json:"Enable,omitempty"`
		} `json:"IPv4Addresses,omitempty"`
		IPv6Addresses []struct {
			Alias             string `json:"Alias,omitempty"`
			IPAddress         string `json:"IPAddress,omitempty"`
			IPAddressStatus   string `json:"IPAddressStatus,omitempty"`
			Origin            string `json:"Origin,omitempty"`
			PreferredLifetime string `json:"PreferredLifetime,omitempty"`
			Prefix            string `json:"Prefix,omitempty"`
			Status            string `json:"Status,omitempty"`
			ValidLifetime     string `json:"ValidLifetime,omitempty"`
			UID               int    `json:"uid,omitempty"`
			Anycast           bool   `json:"Anycast,omitempty"`
			Enable            bool   `json:"Enable,omitempty"`
		} `json:"IPv6Addresses,omitempty"`
		IPv6Prefixes []struct {
			Alias             string `json:"Alias,omitempty"`
			ChildPrefixBits   string `json:"ChildPrefixBits,omitempty"`
			Origin            string `json:"Origin,omitempty"`
			ParentPrefix      string `json:"ParentPrefix,omitempty"`
			PreferredLifetime string `json:"PreferredLifetime,omitempty"`
			Prefix            string `json:"Prefix,omitempty"`
			PrefixStatus      string `json:"PrefixStatus,omitempty"`
			StaticType        string `json:"StaticType,omitempty"`
			Status            string `json:"Status,omitempty"`
			ValidLifetime     string `json:"ValidLifetime,omitempty"`
			UID               int    `json:"uid,omitempty"`
			Enable            bool   `json:"Enable,omitempty"`
			OnLink            bool   `json:"OnLink,omitempty"`
			Autonomous        bool   `json:"Autonomous,omitempty"`
		} `json:"IPv6Prefixes,omitempty"`
		IfcName     string `json:"IfcName,omitempty"`
		LowerLayers string `json:"LowerLayers,omitempty"`
		Name        string `json:"Name,omitempty"`
		Router      string `json:"Router,omitempty"`
		Status      string `json:"Status,omitempty"`
		StoppedBy   string `json:"StoppedBy,omitempty"`
		Type        string `json:"Type,omitempty"`
		Stats       struct {
			BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
			BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
			BytesReceived               string `json:"BytesReceived,omitempty"`
			BytesSent                   string `json:"BytesSent,omitempty"`
			MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
			MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
			PacketsReceived             string `json:"PacketsReceived,omitempty"`
			PacketsSent                 string `json:"PacketsSent,omitempty"`
			UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
			UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
			CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
			DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
			DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
			ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
			ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
			RetransCount                int    `json:"RetransCount,omitempty"`
			UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
		} `json:"Stats,omitempty"`
		AliasID        int  `json:"Alias_id,omitempty"`
		CurrentMTUSize int  `json:"CurrentMTUSize,omitempty"`
		LastChange     int  `json:"LastChange,omitempty"`
		LastStatsReset int  `json:"LastStatsReset,omitempty"`
		MaxMTUSize     int  `json:"MaxMTUSize,omitempty"`
		UID            int  `json:"uid,omitempty"`
		IPv4Enable     bool `json:"IPv4Enable,omitempty"`
		AutoIPEnable   bool `json:"AutoIPEnable,omitempty"`
		DHCPRelease    bool `json:"DHCPRelease,omitempty"`
		Enable         bool `json:"Enable,omitempty"`
		IPv6Enable     bool `json:"IPv6Enable,omitempty"`
		Loopback       bool `json:"Loopback,omitempty"`
		Reset          bool `json:"Reset,omitempty"`
		ResetStats     bool `json:"ResetStats,omitempty"`
		ULAEnable      bool `json:"ULAEnable,omitempty"`
	} `json:"Interfaces,omitempty"`
	Diagnostics struct {
		BroadcomSpeedService struct {
			Algorithm        string `json:"Algorithm,omitempty"`
			DiagnosticsState string `json:"DiagnosticsState,omitempty"`
			Direction        string `json:"Direction,omitempty"`
			DurationSec      string `json:"DurationSec,omitempty"`
			Kbps             string `json:"Kbps,omitempty"`
			LossPercentage   string `json:"LossPercentage,omitempty"`
			MaxKbps          string `json:"MaxKbps,omitempty"`
			MaxSteps         string `json:"MaxSteps,omitempty"`
			Mode             string `json:"Mode,omitempty"`
			PacketLength     string `json:"PacketLength,omitempty"`
			ServerIPAddress  string `json:"ServerIpAddress,omitempty"`
			TCPPort          string `json:"TcpPort,omitempty"`
		} `json:"BroadcomSpeedService,omitempty"`
		DownloadDiagnostics struct {
			BOMTime             string `json:"BOMTime,omitempty"`
			DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
			DownloadTransports  string `json:"DownloadTransports,omitempty"`
			DownloadURL         string `json:"DownloadURL,omitempty"`
			EOMTime             string `json:"EOMTime,omitempty"`
			Interface           string `json:"Interface,omitempty"`
			ROMTime             string `json:"ROMTime,omitempty"`
			TCPOpenRequestTime  string `json:"TCPOpenRequestTime,omitempty"`
			TCPOpenResponseTime string `json:"TCPOpenResponseTime,omitempty"`
			Dscp                int    `json:"DSCP,omitempty"`
			EthernetPriority    int    `json:"EthernetPriority,omitempty"`
			TestBytesReceived   int    `json:"TestBytesReceived,omitempty"`
			TotalBytesReceived  int    `json:"TotalBytesReceived,omitempty"`
		} `json:"DownloadDiagnostics,omitempty"`
		SpeedTest struct {
			DiagnosticsState      string `json:"DiagnosticsState,omitempty"`
			DiagnosticsStatus     string `json:"DiagnosticsStatus,omitempty"`
			Download              string `json:"Download,omitempty"`
			MaxDownload           string `json:"MaxDownload,omitempty"`
			MaxUpload             string `json:"MaxUpload,omitempty"`
			SelectedServerAddress string `json:"SelectedServerAddress,omitempty"`
			ServerList            string `json:"ServerList,omitempty"`
			Upload                string `json:"Upload,omitempty"`
			History               struct {
				BlockTraffic          string `json:"BlockTraffic,omitempty"`
				Download              string `json:"Download,omitempty"`
				Latency               string `json:"Latency,omitempty"`
				SelectedServerAddress string `json:"SelectedServerAddress,omitempty"`
				Timestamp             string `json:"Timestamp,omitempty"`
				Upload                string `json:"Upload,omitempty"`
				Index                 int    `json:"Index,omitempty"`
			} `json:"History,omitempty"`
			Latency         int  `json:"Latency,omitempty"`
			MaxRate         int  `json:"MaxRate,omitempty"`
			ServerTestCount int  `json:"ServerTestCount,omitempty"`
			BlockTraffic    bool `json:"BlockTraffic,omitempty"`
		} `json:"SpeedTest,omitempty"`
		TraceRoute struct {
			DiagnosticsState string `json:"DiagnosticsState,omitempty"`
			Host             string `json:"Host,omitempty"`
			IPAddressUsed    string `json:"IPAddressUsed,omitempty"`
			Interface        string `json:"Interface,omitempty"`
			ProtocolVersion  string `json:"ProtocolVersion,omitempty"`
			RouteHops        []any  `json:"RouteHops,omitempty"`
			Dscp             int    `json:"DSCP,omitempty"`
			DataBlockSize    int    `json:"DataBlockSize,omitempty"`
			MaxHopCount      int    `json:"MaxHopCount,omitempty"`
			NumberOfTries    int    `json:"NumberOfTries,omitempty"`
			ResponseTime     int    `json:"ResponseTime,omitempty"`
			Timeout          int    `json:"Timeout,omitempty"`
		} `json:"TraceRoute,omitempty"`
		UDPEchoConfig struct {
			Interface               string `json:"Interface,omitempty"`
			SourceIPAddress         string `json:"SourceIPAddress,omitempty"`
			TimeFirstPacketReceived string `json:"TimeFirstPacketReceived,omitempty"`
			TimeLastPacketReceived  string `json:"TimeLastPacketReceived,omitempty"`
			BytesReceived           int    `json:"BytesReceived,omitempty"`
			BytesResponded          int    `json:"BytesResponded,omitempty"`
			PacketsReceived         int    `json:"PacketsReceived,omitempty"`
			PacketsResponded        int    `json:"PacketsResponded,omitempty"`
			UDPPort                 int    `json:"UDPPort,omitempty"`
			EchoPlusEnabled         bool   `json:"EchoPlusEnabled,omitempty"`
			EchoPlusSupported       bool   `json:"EchoPlusSupported,omitempty"`
			Enable                  bool   `json:"Enable,omitempty"`
		} `json:"UDPEchoConfig,omitempty"`
		UploadDiagnostics struct {
			BOMTime             string `json:"BOMTime,omitempty"`
			DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
			EOMTime             string `json:"EOMTime,omitempty"`
			Interface           string `json:"Interface,omitempty"`
			ROMTime             string `json:"ROMTime,omitempty"`
			TCPOpenRequestTime  string `json:"TCPOpenRequestTime,omitempty"`
			TCPOpenResponseTime string `json:"TCPOpenResponseTime,omitempty"`
			UploadTransports    string `json:"UploadTransports,omitempty"`
			UploadURL           string `json:"UploadURL,omitempty"`
			Dscp                int    `json:"DSCP,omitempty"`
			EthernetPriority    int    `json:"EthernetPriority,omitempty"`
			TestFileLength      int    `json:"TestFileLength,omitempty"`
			TotalBytesSent      int    `json:"TotalBytesSent,omitempty"`
		} `json:"UploadDiagnostics,omitempty"`
		IPPing struct {
			DiagnosticsState            string `json:"DiagnosticsState,omitempty"`
			Host                        string `json:"Host,omitempty"`
			IPAddressUsed               string `json:"IPAddressUsed,omitempty"`
			Interface                   string `json:"Interface,omitempty"`
			ProtocolVersion             string `json:"ProtocolVersion,omitempty"`
			AverageResponseTime         int    `json:"AverageResponseTime,omitempty"`
			AverageResponseTimeDetailed int    `json:"AverageResponseTimeDetailed,omitempty"`
			Dscp                        int    `json:"DSCP,omitempty"`
			DataBlockSize               int    `json:"DataBlockSize,omitempty"`
			FailureCount                int    `json:"FailureCount,omitempty"`
			MaximumResponseTime         int    `json:"MaximumResponseTime,omitempty"`
			MaximumResponseTimeDetailed int    `json:"MaximumResponseTimeDetailed,omitempty"`
			MinimumResponseTime         int    `json:"MinimumResponseTime,omitempty"`
			MinimumResponseTimeDetailed int    `json:"MinimumResponseTimeDetailed,omitempty"`
			NumberOfRepetitions         int    `json:"NumberOfRepetitions,omitempty"`
			SuccessCount                int    `json:"SuccessCount,omitempty"`
			Timeout                     int    `json:"Timeout,omitempty"`
			Df                          bool   `json:"DF,omitempty"`
		} `json:"IPPing,omitempty"`
		IPv4PingSupported       bool `json:"IPv4PingSupported,omitempty"`
		IPv4TraceRouteSupported bool `json:"IPv4TraceRouteSupported,omitempty"`
		IPv6PingSupported       bool `json:"IPv6PingSupported,omitempty"`
		IPv6TraceRouteSupported bool `json:"IPv6TraceRouteSupported,omitempty"`
	} `json:"Diagnostics,omitempty"`
	TCPConnections int  `json:"TCPConnections,omitempty"`
	XmoConfVersion int  `json:"XmoConfVersion,omitempty"`
	IPv4Capable    bool `json:"IPv4Capable,omitempty"`
	IPv4Enable     bool `json:"IPv4Enable,omitempty"`
	IPv6Capable    bool `json:"IPv6Capable,omitempty"`
	IPv6Enable     bool `json:"IPv6Enable,omitempty"`
}

type nat struct {
	SIPAlgSubnet      string `json:"SipAlgSubnet,omitempty"`
	InterfaceSettings []struct {
		Alias     string `json:"Alias,omitempty"`
		Interface string `json:"Interface,omitempty"`
		SourceIP  string `json:"SourceIP,omitempty"`
		Status    string `json:"Status,omitempty"`
		UID       int    `json:"uid,omitempty"`
		Enable    bool   `json:"Enable,omitempty"`
	} `json:"InterfaceSettings,omitempty"`
	PortMappings []struct {
		RemoteHost            string `json:"RemoteHost,omitempty"`
		Status                string `json:"Status,omitempty"`
		Creator               string `json:"Creator,omitempty"`
		Description           string `json:"Description,omitempty"`
		InternalClient        string `json:"InternalClient,omitempty"`
		ExternalInterface     string `json:"ExternalInterface,omitempty"`
		Target                string `json:"Target,omitempty"`
		InternalInterface     string `json:"InternalInterface,omitempty"`
		Service               string `json:"Service,omitempty"`
		Alias                 string `json:"Alias,omitempty"`
		PublicIP              string `json:"PublicIP,omitempty"`
		Protocol              string `json:"Protocol,omitempty"`
		LeaseStart            string `json:"LeaseStart,omitempty"`
		LeaseDuration         int    `json:"LeaseDuration,omitempty"`
		ExternalPortEndRange  int    `json:"ExternalPortEndRange,omitempty"`
		UID                   int    `json:"uid,omitempty"`
		InternalPort          int    `json:"InternalPort,omitempty"`
		ExternalPort          int    `json:"ExternalPort,omitempty"`
		AllExternalInterfaces bool   `json:"AllExternalInterfaces,omitempty"`
		Enable                bool   `json:"Enable,omitempty"`
	} `json:"PortMappings,omitempty"`
	XSAGEMCOMSIPALGEnable  bool `json:"X_SAGEMCOM_SIPALGEnable,omitempty"`
	IPSecPassthroughEnable bool `json:"IPSecPassthroughEnable,omitempty"`
	PPTPPassthroughEnable  bool `json:"PPTPPassthroughEnable,omitempty"`
}

type ppp struct {
	SupportedNCPs string `json:"SupportedNCPs,omitempty"`
	Interfaces    []struct {
		PPPoA    struct{} `json:"PPPoA,omitempty"`
		PeerAuth struct {
			AuthType string `json:"AuthType,omitempty"`
			Chap     string `json:"Chap,omitempty"`
			Eap      string `json:"Eap,omitempty"`
			MsChap   string `json:"MsChap,omitempty"`
			MsChapV2 string `json:"MsChapV2,omitempty"`
			Pap      string `json:"Pap,omitempty"`
		} `json:"PeerAuth,omitempty"`
		SelfAuth struct {
			Chap     string `json:"Chap,omitempty"`
			Eap      string `json:"Eap,omitempty"`
			MsChap   string `json:"MsChap,omitempty"`
			MsChapV2 string `json:"MsChapV2,omitempty"`
			Pap      string `json:"Pap,omitempty"`
		} `json:"SelfAuth,omitempty"`
		EncryptionProtocol          string `json:"EncryptionProtocol,omitempty"`
		BFState                     string `json:"BFState,omitempty"`
		SupportedNCPs               string `json:"SupportedNCPs,omitempty"`
		CompressionProtocol         string `json:"CompressionProtocol,omitempty"`
		ConnectionStatus            string `json:"ConnectionStatus,omitempty"`
		ConnectionTrigger           string `json:"ConnectionTrigger,omitempty"`
		StoppedBy                   string `json:"StoppedBy,omitempty"`
		DefaultRoute                string `json:"DefaultRoute,omitempty"`
		Status                      string `json:"Status,omitempty"`
		InternalLastConnectionError string `json:"InternalLastConnectionError,omitempty"`
		IfcName                     string `json:"IfcName,omitempty"`
		TransportType               string `json:"TransportType,omitempty"`
		SMUState                    string `json:"SMUState,omitempty"`
		Username                    string `json:"Username,omitempty"`
		Password                    string `json:"Password,omitempty"`
		LastConnectionError         string `json:"LastConnectionError,omitempty"`
		AuthenticationProtocol      string `json:"AuthenticationProtocol,omitempty"`
		Name                        string `json:"Name,omitempty"`
		Alias                       string `json:"Alias,omitempty"`
		LowerLayers                 string `json:"LowerLayers,omitempty"`
		IPCP                        struct {
			DNSServers          string `json:"DNSServers,omitempty"`
			LocalIPAddress      string `json:"LocalIPAddress,omitempty"`
			PassthroughDHCPPool string `json:"PassthroughDHCPPool,omitempty"`
			RemoteIPAddress     string `json:"RemoteIPAddress,omitempty"`
			PassthroughEnable   bool   `json:"PassthroughEnable,omitempty"`
		} `json:"IPCP,omitempty"`
		PPPoE struct {
			ACName              string `json:"ACName,omitempty"`
			OldPPPoESessionOpen string `json:"OldPPPoESessionOpen,omitempty"`
			RemoteMac           string `json:"RemoteMac,omitempty"`
			ServiceName         string `json:"ServiceName,omitempty"`
			SessionID           int    `json:"SessionID,omitempty"`
		} `json:"PPPoE,omitempty"`
		IPv6CP struct {
			LocalInterfaceIdentifier  string `json:"LocalInterfaceIdentifier,omitempty"`
			RemoteInterfaceIdentifier string `json:"RemoteInterfaceIdentifier,omitempty"`
			Eui64UseEnable            bool   `json:"Eui64UseEnable,omitempty"`
		} `json:"IPv6CP,omitempty"`
		Stats struct {
			BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
			BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
			BytesReceived               string `json:"BytesReceived,omitempty"`
			BytesSent                   string `json:"BytesSent,omitempty"`
			MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
			MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
			PacketsReceived             string `json:"PacketsReceived,omitempty"`
			PacketsSent                 string `json:"PacketsSent,omitempty"`
			UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
			UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
			CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
			DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
			DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
			ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
			ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
			RetransCount                int    `json:"RetransCount,omitempty"`
			UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
		} `json:"Stats,omitempty"`
		LastStatsReset                      int  `json:"LastStatsReset,omitempty"`
		HoldoffAuthFailedAdditionalsRetries int  `json:"HoldoffAuthFailedAdditionalsRetries,omitempty"`
		IpcpMaxTerminate                    int  `json:"IpcpMaxTerminate,omitempty"`
		IpcpRestart                         int  `json:"IpcpRestart,omitempty"`
		IpcpTermRestart                     int  `json:"IpcpTermRestart,omitempty"`
		LCPEcho                             int  `json:"LCPEcho,omitempty"`
		LCPEchoRetry                        int  `json:"LCPEchoRetry,omitempty"`
		LastChange                          int  `json:"LastChange,omitempty"`
		IdleDisconnectTime                  int  `json:"IdleDisconnectTime,omitempty"`
		UID                                 int  `json:"uid,omitempty"`
		LcpMaxConfigure                     int  `json:"LcpMaxConfigure,omitempty"`
		LcpMaxTerminate                     int  `json:"LcpMaxTerminate,omitempty"`
		LcpRestart                          int  `json:"LcpRestart,omitempty"`
		LcpTermRestart                      int  `json:"LcpTermRestart,omitempty"`
		WarnDisconnectDelay                 int  `json:"WarnDisconnectDelay,omitempty"`
		MaxFail                             int  `json:"MaxFail,omitempty"`
		MaxMRUSize                          int  `json:"MaxMRUSize,omitempty"`
		AutoDisconnectTime                  int  `json:"AutoDisconnectTime,omitempty"`
		UnitNumber                          int  `json:"UnitNumber,omitempty"`
		ChapMaxResponse                     int  `json:"ChapMaxResponse,omitempty"`
		HoldoffAuthFailedRetries            int  `json:"HoldoffAuthFailedRetries,omitempty"`
		PPPoEMaxPadi                        int  `json:"PPPoEMaxPadi,omitempty"`
		PPPoEMaxPadiInterval                int  `json:"PPPoEMaxPadiInterval,omitempty"`
		ChapResponseRestart                 int  `json:"ChapResponseRestart,omitempty"`
		PPPoEPadiInterval                   int  `json:"PPPoEPadiInterval,omitempty"`
		PPPoEPadrInterval                   int  `json:"PPPoEPadrInterval,omitempty"`
		CurrentMRUSize                      int  `json:"CurrentMRUSize,omitempty"`
		Holdoff                             int  `json:"Holdoff,omitempty"`
		PapMaxAuthReq                       int  `json:"PapMaxAuthReq,omitempty"`
		PapRestart                          int  `json:"PapRestart,omitempty"`
		HoldoffAuthFailedMax                int  `json:"HoldoffAuthFailedMax,omitempty"`
		HoldoffAuthFailedInit               int  `json:"HoldoffAuthFailedInit,omitempty"`
		HoldoffAuthFailedAdd                int  `json:"HoldoffAuthFailedAdd,omitempty"`
		IpcpMaxConfigure                    int  `json:"IpcpMaxConfigure,omitempty"`
		ResetStats                          bool `json:"ResetStats,omitempty"`
		Reset                               bool `json:"Reset,omitempty"`
		PPPoEUseMaxPadiAfterSrvError        bool `json:"PPPoEUseMaxPadiAfterSrvError,omitempty"`
		Enable                              bool `json:"Enable,omitempty"`
		PPPoEPadrIntervalStatic             bool `json:"PPPoEPadrIntervalStatic,omitempty"`
		PPPoEPadi1StRandom                  bool `json:"PPPoEPadi1stRandom,omitempty"`
		HoldoffLcpEchoTimeout               bool `json:"HoldoffLcpEchoTimeout,omitempty"`
		NoCCP                               bool `json:"NoCCP,omitempty"`
		UseRandom1StHoldoff                 bool `json:"UseRandom1stHoldoff,omitempty"`
		HoldoffPeerNoResource               bool `json:"HoldoffPeerNoResource,omitempty"`
		IPCPEnable                          bool `json:"IPCPEnable,omitempty"`
		IPv6CPEnable                        bool `json:"IPv6CPEnable,omitempty"`
	} `json:"Interfaces,omitempty"`
}

type services struct {
	CLIPassword            string `json:"CLIPassword,omitempty"`
	BellInformationalEmail struct {
		DestinationAddress       string `json:"DestinationAddress,omitempty"`
		SMTPPassword             string `json:"SMTPPassword,omitempty"`
		SMTPServerAddress        string `json:"SMTPServerAddress,omitempty"`
		SMTPUsername             string `json:"SMTPUsername,omitempty"`
		SecurePasswordAuthEnable bool   `json:"SecurePasswordAuthEnable,omitempty"`
		ClearTextAuthEnable      bool   `json:"ClearTextAuthEnable,omitempty"`
		Enable                   bool   `json:"Enable,omitempty"`
	} `json:"BellInformationalEmail,omitempty"`
	DynamicDNS struct {
		Clients []struct {
			Alias            string `json:"Alias,omitempty"`
			Interface        string `json:"Interface,omitempty"`
			LastError        string `json:"LastError,omitempty"`
			Password         string `json:"Password,omitempty"`
			ServiceEnum      string `json:"ServiceEnum,omitempty"`
			ServiceReference string `json:"ServiceReference,omitempty"`
			Status           string `json:"Status,omitempty"`
			Username         string `json:"Username,omitempty"`
			Hostnames        []struct {
				LastIP     string `json:"LastIP,omitempty"`
				LastUpdate string `json:"LastUpdate,omitempty"`
				Name       string `json:"Name,omitempty"`
				Status     string `json:"Status,omitempty"`
				UID        int    `json:"uid,omitempty"`
			} `json:"Hostnames,omitempty"`
			RemoteApplicationHTTPSPort int  `json:"RemoteApplicationHTTPSPort,omitempty"`
			UID                        int  `json:"uid,omitempty"`
			Enable                     bool `json:"Enable,omitempty"`
			Hidden                     bool `json:"Hidden,omitempty"`
			Offline                    bool `json:"Offline,omitempty"`
		} `json:"Clients,omitempty"`
		Services []struct {
			Authentication string `json:"Authentication,omitempty"`
			GUIName        string `json:"GUIName,omitempty"`
			Name           string `json:"Name,omitempty"`
			Request        string `json:"Request,omitempty"`
			Server         string `json:"Server,omitempty"`
			MaxRetries     int    `json:"MaxRetries,omitempty"`
			RetryInterval  int    `json:"RetryInterval,omitempty"`
			ServerPort     int    `json:"ServerPort,omitempty"`
			UpdateInterval int    `json:"UpdateInterval,omitempty"`
			UID            int    `json:"uid,omitempty"`
		} `json:"Services,omitempty"`
	} `json:"DynamicDNS,omitempty"`
	VoiceServices   []voiceServices   `json:"VoiceServices,omitempty"`
	StorageServices []storageServices `json:"StorageServices,omitempty"`
	Schedulers      struct {
		Schedulers []any `json:"Schedulers,omitempty"`
	} `json:"Schedulers,omitempty"`
	BellPPPoEPassthrough struct {
		Client []any `json:"Client,omitempty"`
		Enable bool  `json:"Enable,omitempty"`
	} `json:"BellPPPoEPassthrough,omitempty"`
	Plume struct {
		CloudAddress   string `json:"CloudAddress,omitempty"`
		Enable         string `json:"Enable,omitempty"`
		LocationID     string `json:"LocationID,omitempty"`
		PlumeCloudPort string `json:"PlumeCloudPort,omitempty"`
		SavedMode      string `json:"SavedMode,omitempty"`
		SyslogLevel    string `json:"SyslogLevel,omitempty"`
		WhiteList      string `json:"WhiteList,omitempty"`
		OVSDBPort      int    `json:"OVSDBPort,omitempty"`
		Status         int    `json:"Status,omitempty"`
		Restart        bool   `json:"Restart,omitempty"`
	} `json:"Plume,omitempty"`
	Notification struct {
		DestinationEmailAddress            string `json:"DestinationEmailAddress,omitempty"`
		DestinationSMSNumber               string `json:"DestinationSMSNumber,omitempty"`
		CellularFailoverCount              int    `json:"CellularFailoverCount,omitempty"`
		CredentialsRequestCount            int    `json:"CredentialsRequestCount,omitempty"`
		EndOfLifeBatteryNotificationCount  int    `json:"EndOfLifeBatteryNotificationCount,omitempty"`
		CellularFailoverNotificationEnable bool   `json:"CellularFailoverNotificationEnable,omitempty"`
		ContactDisplay                     bool   `json:"ContactDisplay,omitempty"`
		CredentialsRequestEnable           bool   `json:"CredentialsRequestEnable,omitempty"`
		DisplayOnScreen                    bool   `json:"DisplayOnScreen,omitempty"`
		Email                              bool   `json:"Email,omitempty"`
		EndOfLifeBatteryNotificationEnable bool   `json:"EndOfLifeBatteryNotificationEnable,omitempty"`
		IgnoreDisabled                     bool   `json:"IgnoreDisabled,omitempty"`
		IgnoreNullDestinationAddress       bool   `json:"IgnoreNullDestinationAddress,omitempty"`
		Sms                                bool   `json:"SMS,omitempty"`
	} `json:"Notification,omitempty"`
	BellBandwidthMonitoring struct {
		CurrentDate  string `json:"CurrentDate,omitempty"`
		DateList     string `json:"DateList,omitempty"`
		PreviousDate string `json:"PreviousDate,omitempty"`
		Hosts        []any  `json:"Hosts,omitempty"`
		Stats        struct {
			ReceivedList        string `json:"ReceivedList,omitempty"`
			SentList            string `json:"SentList,omitempty"`
			CurrentDayReceived  int    `json:"CurrentDayReceived,omitempty"`
			CurrentDaySent      int    `json:"CurrentDaySent,omitempty"`
			PreviousDayReceived int    `json:"PreviousDayReceived,omitempty"`
			PreviousDaySent     int    `json:"PreviousDaySent,omitempty"`
		} `json:"Stats,omitempty"`
		BillingDay          int `json:"BillingDay,omitempty"`
		HostNumberOfEntries int `json:"HostNumberOfEntries,omitempty"`
		RetentionPeriod     int `json:"RetentionPeriod,omitempty"`
	} `json:"BellBandwidthMonitoring,omitempty"`
	BellIGMPStatistics struct {
		Stream                   []any `json:"Stream,omitempty"`
		MessagesReceived         int   `json:"MessagesReceived,omitempty"`
		QueriesReceived          int   `json:"QueriesReceived,omitempty"`
		V2LeaveMessagesReceived  int   `json:"V2LeaveMessagesReceived,omitempty"`
		V2ReportMessagesReceived int   `json:"V2ReportMessagesReceived,omitempty"`
		V3ReportMessagesReceived int   `json:"V3ReportMessagesReceived,omitempty"`
		Enable                   bool  `json:"Enable,omitempty"`
	} `json:"BellIGMPStatistics,omitempty"`
	BellNetworkCfg struct {
		AutoSensingMode            string `json:"AutoSensingMode,omitempty"`
		FirmwareRollbackMinVersion string `json:"FirmwareRollbackMinVersion,omitempty"`
		InterfaceType              string `json:"InterfaceType,omitempty"`
		KnownSTBMacAddresses       string `json:"KnownSTBMacAddresses,omitempty"`
		KnownVAPMacAddresses       string `json:"KnownVAPMacAddresses,omitempty"`
		SetBridgeMode              string `json:"SetBridgeMode,omitempty"`
		SetIPTVMode                string `json:"SetIPTVMode,omitempty"`
		SetIVoIPInterface          string `json:"SetIVoIPInterface,omitempty"`
		SetInternetMode            string `json:"SetInternetMode,omitempty"`
		SetServicesMode            string `json:"SetServicesMode,omitempty"`
		VoiceAllowedWANModes       string `json:"VoiceAllowedWANModes,omitempty"`
		WanMode                    string `json:"WanMode,omitempty"`
		WanType                    string `json:"WanType,omitempty"`
		AdvancedDMZ                struct {
			AdvancedDMZhost string `json:"AdvancedDMZhost,omitempty"`
			Status          string `json:"Status,omitempty"`
			Enable          bool   `json:"Enable,omitempty"`
		} `json:"AdvancedDMZ,omitempty"`
		BandwidthMonitoring struct {
			Status           string `json:"Status,omitempty"`
			CollectingPeriod int    `json:"CollectingPeriod,omitempty"`
			HistoryPeriod    int    `json:"HistoryPeriod,omitempty"`
			Enable           bool   `json:"Enable,omitempty"`
		} `json:"BandwidthMonitoring,omitempty"`
		TemperatureMonitoring struct {
			Mode                        string `json:"Mode,omitempty"`
			Thresholds                  string `json:"Thresholds,omitempty"`
			ListFeaturesPreviousState   int    `json:"ListFeaturesPreviousState,omitempty"`
			ListFeaturesShutdown        int    `json:"ListFeaturesShutdown,omitempty"`
			RebootCountDown             int    `json:"RebootCountDown,omitempty"`
			Temperature                 int    `json:"Temperature,omitempty"`
			TemperatureMonitoringPeriod int    `json:"TemperatureMonitoringPeriod,omitempty"`
			DisplayInUI                 bool   `json:"DisplayInUI,omitempty"`
			DisplayOnScreen             bool   `json:"DisplayOnScreen,omitempty"`
		} `json:"TemperatureMonitoring,omitempty"`
		WANSSHBlockTimer            int  `json:"WANSSHBlockTimer,omitempty"`
		WANSSHSessionTimer          int  `json:"WANSSHSessionTimer,omitempty"`
		SetIPTVInterface            int  `json:"SetIPTVInterface,omitempty"`
		ButtonOsmEnable             bool `json:"ButtonOsmEnable,omitempty"`
		FirmwareRollback            bool `json:"FirmwareRollback,omitempty"`
		IPTVEnable                  bool `json:"IPTVEnable,omitempty"`
		IPv6Allowed                 bool `json:"IPv6Allowed,omitempty"`
		LanOsmEnable                bool `json:"LanOsmEnable,omitempty"`
		LedOsmEnable                bool `json:"LedOsmEnable,omitempty"`
		ResetIPTVService            bool `json:"ResetIPTVService,omitempty"`
		ResetInternetService        bool `json:"ResetInternetService,omitempty"`
		ResetVoiceService           bool `json:"ResetVoiceService,omitempty"`
		SSHEnable                   bool `json:"SSHEnable,omitempty"`
		ScreenOsmEnable             bool `json:"ScreenOsmEnable,omitempty"`
		TVOsmEnable                 bool `json:"TVOsmEnable,omitempty"`
		TelnetEnable                bool `json:"TelnetEnable,omitempty"`
		TemperatureMonitorOsmEnable bool `json:"TemperatureMonitorOsmEnable,omitempty"`
		VoiceEnable                 bool `json:"VoiceEnable,omitempty"`
		WanModeVoiceLock            bool `json:"WanModeVoiceLock,omitempty"`
	} `json:"BellNetworkCfg,omitempty"`
	BellCredentialsRequestEmail struct {
		RequestCount int `json:"RequestCount,omitempty"`
	} `json:"BellCredentialsRequestEmail,omitempty"`
	Activation struct {
		RequestCount int `json:"RequestCount,omitempty"`
	} `json:"Activation,omitempty"`
	IPTVDNSStatus     bool `json:"IPTVDNSStatus,omitempty"`
	InternetDNSStatus bool `json:"InternetDNSStatus,omitempty"`
	ServicesDNSStatus bool `json:"ServicesDNSStatus,omitempty"`
	SetLEDState       bool `json:"SetLEDState,omitempty"`
	VoiceOnlyEnable   bool `json:"VoiceOnlyEnable,omitempty"`
}

type voiceServices struct {
	Alias             string          `json:"Alias,omitempty"`
	CallingNumber     string          `json:"CallingNumber,omitempty"`
	RegionalOptions   []any           `json:"RegionalOptions,omitempty"`
	Messages          []any           `json:"Messages,omitempty"`
	VoiceProfiles     []voiceProfiles `json:"VoiceProfiles,omitempty"`
	VoIPProfiles      []any           `json:"VoIPProfiles,omitempty"`
	Contacts          []any           `json:"Contacts,omitempty"`
	ExtensionProfiles []any           `json:"ExtensionProfiles,omitempty"`
	NetworkProfiles   []any           `json:"NetworkProfiles,omitempty"`
	PhyInterfaces     []phyInterfaces `json:"PhyInterfaces,omitempty"`
	Tone              struct {
		Descriptions []any `json:"Descriptions,omitempty"`
	} `json:"Tone,omitempty"`
	Battery struct {
		NotificationFile                  string `json:"NotificationFile,omitempty"`
		NotificationInterval              int    `json:"NotificationInterval,omitempty"`
		CriticalBatteryNotificationEnable bool   `json:"CriticalBatteryNotificationEnable,omitempty"`
		Enable                            bool   `json:"Enable,omitempty"`
		LowBatteryNotificationEnable      bool   `json:"LowBatteryNotificationEnable,omitempty"`
	} `json:"Battery,omitempty"`
	SIP struct {
		Registrars               []any `json:"Registrars,omitempty"`
		RegistrarNumberOfEntries int   `json:"RegistrarNumberOfEntries,omitempty"`
	} `json:"SIP,omitempty"`
	XSAGEMCOMVoiceManagement struct {
		BfProcessName                  string `json:"BfProcessName,omitempty"`
		DataInterface                  string `json:"DataInterface,omitempty"`
		FxoInterface                   string `json:"FxoInterface,omitempty"`
		VoipBackupInterface            string `json:"VoipBackupInterface,omitempty"`
		VoipInterface                  string `json:"VoipInterface,omitempty"`
		BfProcessUnexpectedTerminateNb int    `json:"BfProcessUnexpectedTerminateNb,omitempty"`
		AutoStart                      bool   `json:"AutoStart,omitempty"`
		BfProcessCertifMode            bool   `json:"BfProcessCertifMode,omitempty"`
		BfProcessDebugMode             bool   `json:"BfProcessDebugMode,omitempty"`
		IP6Enable                      bool   `json:"IP6Enable,omitempty"`
		MonitoringEnable               bool   `json:"MonitoringEnable,omitempty"`
		UseOption120                   bool   `json:"UseOption120,omitempty"`
		VoiceCallEmergencyInProgress   bool   `json:"VoiceCallEmergencyInProgress,omitempty"`
		VoiceConfigLocked              bool   `json:"VoiceConfigLocked,omitempty"`
		VoiceServiceEnable             bool   `json:"VoiceServiceEnable,omitempty"`
	} `json:"X_SAGEMCOM_VoiceManagement,omitempty"`
	VoiceMail struct {
		NumberRemoteExt string `json:"NumberRemoteExt,omitempty"`
		SMTP            struct {
			From     string `json:"From,omitempty"`
			Login    string `json:"Login,omitempty"`
			Password string `json:"Password,omitempty"`
			Server   string `json:"Server,omitempty"`
		} `json:"SMTP,omitempty"`
		MaxAccess       int `json:"MaxAccess,omitempty"`
		Number          int `json:"Number,omitempty"`
		NumberRemoteInt int `json:"NumberRemoteInt,omitempty"`
	} `json:"VoiceMail,omitempty"`
	IVR struct {
		AlternativeShortNumber string `json:"AlternativeShortNumber,omitempty"`
		ExternalNumber         string `json:"ExternalNumber,omitempty"`
		Name                   string `json:"Name,omitempty"`
		RepeatDelay            string `json:"RepeatDelay,omitempty"`
		RepeatTime             string `json:"RepeatTime,omitempty"`
		Keys                   []any  `json:"Keys,omitempty"`
		DayNightSchedule       struct {
			ManagementNightDays []any `json:"ManagementNightDays,omitempty"`
			Enable              bool  `json:"Enable,omitempty"`
		} `json:"DayNightSchedule,omitempty"`
		DirectCallRestrictionID int  `json:"DirectCallRestrictionID,omitempty"`
		Number                  int  `json:"Number,omitempty"`
		RingbackEnable          bool `json:"RingbackEnable,omitempty"`
	} `json:"IVR,omitempty"`
	CallControl struct {
		TerminationDigit        string `json:"TerminationDigit,omitempty"`
		CallLogs                []any  `json:"CallLogs,omitempty"`
		IncomingMaps            []any  `json:"IncomingMaps,omitempty"`
		Mailboxs                []any  `json:"Mailboxs,omitempty"`
		NumberingPlans          []any  `json:"NumberingPlans,omitempty"`
		OutgoingMaps            []any  `json:"OutgoingMaps,omitempty"`
		CallLogNumberOfEntries  int    `json:"CallLogNumberOfEntries,omitempty"`
		InterDigitTimerOpen     int    `json:"InterDigitTimerOpen,omitempty"`
		InterDigitTimerStd      int    `json:"InterDigitTimerStd,omitempty"`
		MaxIncomingCallLogCount int    `json:"MaxIncomingCallLogCount,omitempty"`
		MaxOutgoingCallLogCount int    `json:"MaxOutgoingCallLogCount,omitempty"`
	} `json:"CallControl,omitempty"`
	XSAGEMCOMVoiceBehavior struct {
		LocalAnnouncement struct {
			StopDigitList string `json:"StopDigitList,omitempty"`
			PauseDelayMs  int    `json:"PauseDelayMs,omitempty"`
			RepeatNumber  int    `json:"RepeatNumber,omitempty"`
			StartDelayMs  int    `json:"StartDelayMs,omitempty"`
		} `json:"LocalAnnouncement,omitempty"`
		BackupInterface struct {
			FailOverInterfaceDownDuringCallTimer int `json:"FailOverInterfaceDownDuringCallTimer,omitempty"`
			FailOverInterfaceDownTimer           int `json:"FailOverInterfaceDownTimer,omitempty"`
			FailOverInviteNoRespTimer            int `json:"FailOverInviteNoRespTimer,omitempty"`
			FailOverRegisterNoRespTimer          int `json:"FailOverRegisterNoRespTimer,omitempty"`
		} `json:"BackupInterface,omitempty"`
	} `json:"X_SAGEMCOM_VoiceBehavior,omitempty"`
	Capabilities struct {
		Regions                string `json:"Regions,omitempty"`
		RingFileFormats        string `json:"RingFileFormats,omitempty"`
		SRTPEncryptionKeySizes string `json:"SRTPEncryptionKeySizes,omitempty"`
		SRTPKeyingMethods      string `json:"SRTPKeyingMethods,omitempty"`
		SignalingProtocols     string `json:"SignalingProtocols,omitempty"`
		ToneFileFormats        string `json:"ToneFileFormats,omitempty"`
		Mgcp                   struct {
			Extensions string `json:"Extensions,omitempty"`
		} `json:"MGCP,omitempty"`
		SIP struct {
			Extensions                 string `json:"Extensions,omitempty"`
			Role                       string `json:"Role,omitempty"`
			TLSAuthenticationKeySizes  string `json:"TLSAuthenticationKeySizes,omitempty"`
			TLSAuthenticationProtocols string `json:"TLSAuthenticationProtocols,omitempty"`
			TLSEncryptionKeySizes      string `json:"TLSEncryptionKeySizes,omitempty"`
			TLSEncryptionProtocols     string `json:"TLSEncryptionProtocols,omitempty"`
			TLSKeyExchangeProtocols    string `json:"TLSKeyExchangeProtocols,omitempty"`
			Transports                 string `json:"Transports,omitempty"`
			URISchemes                 string `json:"URISchemes,omitempty"`
			EventSubscription          bool   `json:"EventSubscription,omitempty"`
			ResponseMap                bool   `json:"ResponseMap,omitempty"`
		} `json:"SIP,omitempty"`
		H323 struct {
			H235AuthenticationMethods string `json:"H235AuthenticationMethods,omitempty"`
			FastStart                 bool   `json:"FastStart,omitempty"`
		} `json:"H323,omitempty"`
		Codecs                     []any `json:"Codecs,omitempty"`
		MaxLineCount               int   `json:"MaxLineCount,omitempty"`
		MaxProfileCount            int   `json:"MaxProfileCount,omitempty"`
		MaxSessionCount            int   `json:"MaxSessionCount,omitempty"`
		MaxSessionsPerLine         int   `json:"MaxSessionsPerLine,omitempty"`
		ButtonMap                  bool  `json:"ButtonMap,omitempty"`
		DSCPCoupled                bool  `json:"DSCPCoupled,omitempty"`
		DigitMap                   bool  `json:"DigitMap,omitempty"`
		EthernetTaggingCoupled     bool  `json:"EthernetTaggingCoupled,omitempty"`
		FaxPassThrough             bool  `json:"FaxPassThrough,omitempty"`
		FaxT38                     bool  `json:"FaxT38,omitempty"`
		FileBasedRingGeneration    bool  `json:"FileBasedRingGeneration,omitempty"`
		FileBasedToneGeneration    bool  `json:"FileBasedToneGeneration,omitempty"`
		ModemPassThrough           bool  `json:"ModemPassThrough,omitempty"`
		NumberingPlan              bool  `json:"NumberingPlan,omitempty"`
		PSTNSoftSwitchOver         bool  `json:"PSTNSoftSwitchOver,omitempty"`
		PatternBasedRingGeneration bool  `json:"PatternBasedRingGeneration,omitempty"`
		PatternBasedToneGeneration bool  `json:"PatternBasedToneGeneration,omitempty"`
		Rtcp                       bool  `json:"RTCP,omitempty"`
		RTPRedundancy              bool  `json:"RTPRedundancy,omitempty"`
		RingDescriptionsEditable   bool  `json:"RingDescriptionsEditable,omitempty"`
		RingGeneration             bool  `json:"RingGeneration,omitempty"`
		RingPatternEditable        bool  `json:"RingPatternEditable,omitempty"`
		Srtp                       bool  `json:"SRTP,omitempty"`
		ToneDescriptionsEditable   bool  `json:"ToneDescriptionsEditable,omitempty"`
		ToneGeneration             bool  `json:"ToneGeneration,omitempty"`
		VoicePortTests             bool  `json:"VoicePortTests,omitempty"`
	} `json:"Capabilities,omitempty"`
	XSAGEMCOMMaxLicense     int  `json:"X_SAGEMCOM_MaxLicense,omitempty"`
	UID                     int  `json:"uid,omitempty"`
	XSAGEMCOMPSTNEnable     bool `json:"X_SAGEMCOM_PSTNEnable,omitempty"`
	XSAGEMCOMDECTBaseEnable bool `json:"X_SAGEMCOM_DECTBaseEnable,omitempty"`
	Enable                  bool `json:"Enable,omitempty"`
}

type voiceProfiles struct {
	DTMFMethod                       string `json:"DTMFMethod,omitempty"`
	DTMFMethodG711                   string `json:"DTMFMethodG711,omitempty"`
	Enable                           string `json:"Enable,omitempty"`
	FaxPassThrough                   string `json:"FaxPassThrough,omitempty"`
	LastBackupInterfaceTime          string `json:"LastBackupInterfaceTime,omitempty"`
	ModemPassThrough                 string `json:"ModemPassThrough,omitempty"`
	Name                             string `json:"Name,omitempty"`
	PLCMode                          string `json:"PLCMode,omitempty"`
	Region                           string `json:"Region,omitempty"`
	STUNServer                       string `json:"STUNServer,omitempty"`
	SignalingProtocol                string `json:"SignalingProtocol,omitempty"`
	Status                           string `json:"Status,omitempty"`
	VoiceBackupInterfaceStatus       string `json:"VoiceBackupInterfaceStatus,omitempty"`
	VoiceBackupInterfaceStatusReason string `json:"VoiceBackupInterfaceStatusReason,omitempty"`
	DigitMaps                        []any  `json:"DigitMaps,omitempty"`
	FQDNServers                      []any  `json:"FQDNServers,omitempty"`
	Lines                            []struct {
		CallState        string `json:"CallState,omitempty"`
		DirectoryNumber  string `json:"DirectoryNumber,omitempty"`
		Enable           string `json:"Enable,omitempty"`
		ErrorCode        string `json:"ErrorCode,omitempty"`
		Name             string `json:"Name,omitempty"`
		PhyReferenceList string `json:"PhyReferenceList,omitempty"`
		Status           string `json:"Status,omitempty"`
		StatusReason     string `json:"StatusReason,omitempty"`
		VoiceMail        string `json:"VoiceMail,omitempty"`
		CallingFeatures  struct {
			CallForwardOnBusyActCode          string `json:"CallForwardOnBusyActCode,omitempty"`
			CallForwardOnBusyDeactCode        string `json:"CallForwardOnBusyDeactCode,omitempty"`
			CallForwardOnBusyNumber           string `json:"CallForwardOnBusyNumber,omitempty"`
			CallForwardOnNoAnswerActCode      string `json:"CallForwardOnNoAnswerActCode,omitempty"`
			CallForwardOnNoAnswerDeactCode    string `json:"CallForwardOnNoAnswerDeactCode,omitempty"`
			CallForwardOnNoAnswerNumber       string `json:"CallForwardOnNoAnswerNumber,omitempty"`
			CallForwardUnconditionalActCode   string `json:"CallForwardUnconditionalActCode,omitempty"`
			CallForwardUnconditionalDeactCode string `json:"CallForwardUnconditionalDeactCode,omitempty"`
			CallForwardUnconditionalNumber    string `json:"CallForwardUnconditionalNumber,omitempty"`
			CallParkingMode                   string `json:"CallParkingMode,omitempty"`
			CallWaitingStatus                 string `json:"CallWaitingStatus,omitempty"`
			CallerIDName                      string `json:"CallerIDName,omitempty"`
			ConferenceCallingStatus           string `json:"ConferenceCallingStatus,omitempty"`
			HotLineWarmLineURI                string `json:"HotLineWarmLineURI,omitempty"`
			PermanentCLIRActCode              string `json:"PermanentCLIRActCode,omitempty"`
			PermanentCLIRDeactCode            string `json:"PermanentCLIRDeactCode,omitempty"`
			WarmLineActCode                   string `json:"WarmLineActCode,omitempty"`
			WarmLineDeactCode                 string `json:"WarmLineDeactCode,omitempty"`
			CallForwardOnNoAnswerRingCount    int    `json:"CallForwardOnNoAnswerRingCount,omitempty"`
			CallParkingTimeout                int    `json:"CallParkingTimeout,omitempty"`
			CallWaitingTimeout                int    `json:"CallWaitingTimeout,omitempty"`
			ConferenceCallingSessionCount     int    `json:"ConferenceCallingSessionCount,omitempty"`
			DNDNbCallAttempts                 int    `json:"DND_NbCallAttempts,omitempty"`
			DNDNoActivityTimeout              int    `json:"DND_NoActivityTimeout,omitempty"`
			MaxSessions                       int    `json:"MaxSessions,omitempty"`
			WarmLineTimeout                   int    `json:"WarmLineTimeout,omitempty"`
			WarmLineEnable                    bool   `json:"WarmLineEnable,omitempty"`
			AnonymousCalEnable                bool   `json:"AnonymousCalEnable,omitempty"`
			AnonymousCallBlockEnable          bool   `json:"AnonymousCallBlockEnable,omitempty"`
			BlindCallTransferEnable           bool   `json:"BlindCallTransferEnable,omitempty"`
			CallDeclineEnable                 bool   `json:"CallDeclineEnable,omitempty"`
			CallForwardOnBusyEnable           bool   `json:"CallForwardOnBusyEnable,omitempty"`
			CallForwardOnNoAnswerEnable       bool   `json:"CallForwardOnNoAnswerEnable,omitempty"`
			CallForwardUnconditionalEnable    bool   `json:"CallForwardUnconditionalEnable,omitempty"`
			CallParkingEnable                 bool   `json:"CallParkingEnable,omitempty"`
			CallReturnEnable                  bool   `json:"CallReturnEnable,omitempty"`
			CallTransferEnable                bool   `json:"CallTransferEnable,omitempty"`
			CallWaitingEnable                 bool   `json:"CallWaitingEnable,omitempty"`
			CallerIDEnable                    bool   `json:"CallerIDEnable,omitempty"`
			CallerIDNameEnable                bool   `json:"CallerIDNameEnable,omitempty"`
			DoNotDisturbEnable                bool   `json:"DoNotDisturbEnable,omitempty"`
			DoubleCallEnable                  bool   `json:"DoubleCallEnable,omitempty"`
			HotLineEnable                     bool   `json:"HotLineEnable,omitempty"`
			MWIEnable                         bool   `json:"MWIEnable,omitempty"`
			MessageWaiting                    bool   `json:"MessageWaiting,omitempty"`
			MultiCallEnable                   bool   `json:"MultiCallEnable,omitempty"`
			OutgoingCallEnable                bool   `json:"OutgoingCallEnable,omitempty"`
			PermanentCLIREnable               bool   `json:"PermanentCLIREnable,omitempty"`
			RepeatDialEnable                  bool   `json:"RepeatDialEnable,omitempty"`
			XSAGEMCOMCLIPEnable               bool   `json:"X_SAGEMCOM_CLIPEnable,omitempty"`
			XSAGEMCOMCNIPEnable               bool   `json:"X_SAGEMCOM_CNIPEnable,omitempty"`
			XSAGEMCOMConferenceEnable         bool   `json:"X_SAGEMCOM_ConferenceEnable,omitempty"`
			XSAGEMCOMVMWIEnable               bool   `json:"X_SAGEMCOM_VMWIEnable,omitempty"`
		} `json:"CallingFeatures,omitempty"`
		Codec struct {
			ReceiveCodec  string `json:"ReceiveCodec,omitempty"`
			TransmitCodec string `json:"TransmitCodec,omitempty"`
			Lists         []struct {
				Codec                        string `json:"Codec,omitempty"`
				PacketizationPeriod          string `json:"PacketizationPeriod,omitempty"`
				BitRate                      int    `json:"BitRate,omitempty"`
				EntryID                      int    `json:"EntryID,omitempty"`
				PreferredPacketisationPeriod int    `json:"PreferredPacketisationPeriod,omitempty"`
				Priority                     int    `json:"Priority,omitempty"`
				UID                          int    `json:"uid,omitempty"`
				Enable                       bool   `json:"Enable,omitempty"`
				SilenceSuppression           bool   `json:"SilenceSuppression,omitempty"`
			} `json:"Lists,omitempty"`
			ReceiveBitRate              int  `json:"ReceiveBitRate,omitempty"`
			TransmitBitRate             int  `json:"TransmitBitRate,omitempty"`
			TransmitPacketizationPeriod int  `json:"TransmitPacketizationPeriod,omitempty"`
			ReceiveSilenceSuppression   bool `json:"ReceiveSilenceSuppression,omitempty"`
			TransmitSilenceSuppression  bool `json:"TransmitSilenceSuppression,omitempty"`
		} `json:"Codec,omitempty"`
		Ringer struct {
			Descriptions []struct {
				RingFile    string `json:"RingFile,omitempty"`
				RingName    string `json:"RingName,omitempty"`
				EntryID     int    `json:"EntryID,omitempty"`
				RingPattern int    `json:"RingPattern,omitempty"`
				UID         int    `json:"uid,omitempty"`
				RingEnable  bool   `json:"RingEnable,omitempty"`
			} `json:"Descriptions,omitempty"`
			Events   []any `json:"Events,omitempty"`
			Patterns []any `json:"Patterns,omitempty"`
		} `json:"Ringer,omitempty"`
		Sessions []any `json:"Sessions,omitempty"`
		Stats    struct {
			XSAGEMCOMLastCalledNumber        string `json:"X_SAGEMCOM_LastCalledNumber,omitempty"`
			AverageFarEndInterarrivalJitter  int    `json:"AverageFarEndInterarrivalJitter,omitempty"`
			AverageReceiveInterarrivalJitter int    `json:"AverageReceiveInterarrivalJitter,omitempty"`
			AverageRoundTripDelay            int    `json:"AverageRoundTripDelay,omitempty"`
			BytesReceived                    int    `json:"BytesReceived,omitempty"`
			BytesSent                        int    `json:"BytesSent,omitempty"`
			CallsDropped                     int    `json:"CallsDropped,omitempty"`
			FarEndInterarrivalJitter         int    `json:"FarEndInterarrivalJitter,omitempty"`
			FarEndPacketLossRate             int    `json:"FarEndPacketLossRate,omitempty"`
			IncomingCallsAnswered            int    `json:"IncomingCallsAnswered,omitempty"`
			IncomingCallsConnected           int    `json:"IncomingCallsConnected,omitempty"`
			IncomingCallsFailed              int    `json:"IncomingCallsFailed,omitempty"`
			IncomingCallsReceived            int    `json:"IncomingCallsReceived,omitempty"`
			OutgoingCallsAnswered            int    `json:"OutgoingCallsAnswered,omitempty"`
			OutgoingCallsAttempted           int    `json:"OutgoingCallsAttempted,omitempty"`
			OutgoingCallsConnected           int    `json:"OutgoingCallsConnected,omitempty"`
			OutgoingCallsFailed              int    `json:"OutgoingCallsFailed,omitempty"`
			Overruns                         int    `json:"Overruns,omitempty"`
			PacketsLost                      int    `json:"PacketsLost,omitempty"`
			PacketsReceived                  int    `json:"PacketsReceived,omitempty"`
			PacketsSent                      int    `json:"PacketsSent,omitempty"`
			ReceiveInterarrivalJitter        int    `json:"ReceiveInterarrivalJitter,omitempty"`
			ReceivePacketLossRate            int    `json:"ReceivePacketLossRate,omitempty"`
			RoundTripDelay                   int    `json:"RoundTripDelay,omitempty"`
			ServerDownTime                   int    `json:"ServerDownTime,omitempty"`
			TotalCallTime                    int    `json:"TotalCallTime,omitempty"`
			Underruns                        int    `json:"Underruns,omitempty"`
			ResetStatistics                  bool   `json:"ResetStatistics,omitempty"`
		} `json:"Stats,omitempty"`
		VoiceProcessing struct {
			EchoCancellationTail   int  `json:"EchoCancellationTail,omitempty"`
			ReceiveGain            int  `json:"ReceiveGain,omitempty"`
			TransmitGain           int  `json:"TransmitGain,omitempty"`
			EchoCancellationEnable bool `json:"EchoCancellationEnable,omitempty"`
			EchoCancellationInUse  bool `json:"EchoCancellationInUse,omitempty"`
		} `json:"VoiceProcessing,omitempty"`
		LineID               int  `json:"LineId,omitempty"`
		RingVolumeStatus     int  `json:"RingVolumeStatus,omitempty"`
		XSAGEMCOMMaxSessions int  `json:"X_SAGEMCOM_MaxSessions,omitempty"`
		UID                  int  `json:"uid,omitempty"`
		RingMuteStatus       bool `json:"RingMuteStatus,omitempty"`
	} `json:"Lines,omitempty"`
	ServiceProviderInfo struct {
		ContactPhoneNumber string `json:"ContactPhoneNumber,omitempty"`
		EmailAddress       string `json:"EmailAddress,omitempty"`
		Name               string `json:"Name,omitempty"`
		URL                string `json:"URL,omitempty"`
	} `json:"ServiceProviderInfo,omitempty"`
	ButtonMap struct {
		Buttons         []any `json:"Buttons,omitempty"`
		NumberOfButtons int   `json:"NumberOfButtons,omitempty"`
	} `json:"ButtonMap,omitempty"`
	Emergency struct {
		DigitMap                      string `json:"DigitMap,omitempty"`
		EnhancedCalledPartyHoldTimer  int    `json:"EnhancedCalledPartyHoldTimer,omitempty"`
		CalledPartyHoldTimer          int    `json:"CalledPartyHoldTimer,omitempty"`
		AutoRingBackEnable            bool   `json:"AutoRingBackEnable,omitempty"`
		BlockCallingFeaturesEnable    bool   `json:"BlockCallingFeaturesEnable,omitempty"`
		CalledPartyHoldEnable         bool   `json:"CalledPartyHoldEnable,omitempty"`
		Enable                        bool   `json:"Enable,omitempty"`
		EnhancedCalledPartyHoldEnable bool   `json:"EnhancedCalledPartyHoldEnable,omitempty"`
	} `json:"Emergency,omitempty"`
	FaxT38 struct {
		TCFMethod           string `json:"TCFMethod,omitempty"`
		BitRate             int    `json:"BitRate,omitempty"`
		HighSpeedPacketRate int    `json:"HighSpeedPacketRate,omitempty"`
		HighSpeedRedundancy int    `json:"HighSpeedRedundancy,omitempty"`
		LowSpeedRedundancy  int    `json:"LowSpeedRedundancy,omitempty"`
		ECMTransport        bool   `json:"ECMTransport,omitempty"`
		Enable              bool   `json:"Enable,omitempty"`
	} `json:"FaxT38,omitempty"`
	NumberingPlan struct {
		XSAGEMCOMEndOfNumberingDigit string `json:"X_SAGEMCOM_EndOfNumberingDigit,omitempty"`
		PrefixInfos                  []any  `json:"PrefixInfos,omitempty"`
		FirstDigitTimer              int    `json:"FirstDigitTimer,omitempty"`
		FlashHookTimer               int    `json:"FlashHookTimer,omitempty"`
		InterDigitTimerOpen          int    `json:"InterDigitTimerOpen,omitempty"`
		InterDigitTimerStd           int    `json:"InterDigitTimerStd,omitempty"`
		InvalidNumberTone            int    `json:"InvalidNumberTone,omitempty"`
		MaximumNumberOfDigits        int    `json:"MaximumNumberOfDigits,omitempty"`
		MinimumNumberOfDigits        int    `json:"MinimumNumberOfDigits,omitempty"`
	} `json:"NumberingPlan,omitempty"`

	BackupInterfaceSwitchCounter        int  `json:"BackupInterfaceSwitchCounter,omitempty"`
	FQDNServerNumberOfEntries           int  `json:"FQDNServerNumberOfEntries,omitempty"`
	MaxSessions                         int  `json:"MaxSessions,omitempty"`
	NonVoiceBandwidthReservedDownstream int  `json:"NonVoiceBandwidthReservedDownstream,omitempty"`
	NonVoiceBandwidthReservedUpstream   int  `json:"NonVoiceBandwidthReservedUpstream,omitempty"`
	NumberOfLines                       int  `json:"NumberOfLines,omitempty"`
	UID                                 int  `json:"uid,omitempty"`
	DigitMapEnable                      bool `json:"DigitMapEnable,omitempty"`
	PSTNFailOver                        bool `json:"PSTNFailOver,omitempty"`
	Reset                               bool `json:"Reset,omitempty"`
	STUNEnable                          bool `json:"STUNEnable,omitempty"`
	VoiceBackupInterfaceEnable          bool `json:"VoiceBackupInterfaceEnable,omitempty"`
}

type phyInterfaces struct {
	Tests struct {
		TestResult   string `json:"TestResult,omitempty"`
		TestSelector string `json:"TestSelector,omitempty"`
		TestState    string `json:"TestState,omitempty"`
	} `json:"Tests,omitempty"`
	Alias            string `json:"Alias,omitempty"`
	Description      string `json:"Description,omitempty"`
	FXSStatus        string `json:"FXSStatus,omitempty"`
	Number           string `json:"Number,omitempty"`
	OutGoingLine     string `json:"OutGoingLine,omitempty"`
	PhyInterfaceType string `json:"PhyInterfaceType,omitempty"`
	PhyPort          string `json:"PhyPort,omitempty"`
	Status           string `json:"Status,omitempty"`
	StatusTime       string `json:"StatusTime,omitempty"`
	CodecLists       []struct {
		FXSStatus string `json:"FXSStatus,omitempty"`
		EntryID   int    `json:"EntryID,omitempty"`
		UID       int    `json:"uid,omitempty"`
	} `json:"CodecLists,omitempty"`
	XSagemcomDectPp struct {
		Control                                 string `json:"Control,omitempty"`
		HandsetRole                             string `json:"HandsetRole,omitempty"`
		HandsetType                             string `json:"HandsetType,omitempty"`
		HardwareVersion                         string `json:"HardwareVersion,omitempty"`
		InternationalPortableEquipementIdentity string `json:"InternationalPortableEquipementIdentity,omitempty"`
		InternationalPortableUserIdentity       string `json:"InternationalPortableUserIdentity,omitempty"`
		LastUpdateDateTime                      string `json:"LastUpdateDateTime,omitempty"`
		PortableAccessRightsKey                 string `json:"PortableAccessRightsKey,omitempty"`
		RFPIAttachedTo                          string `json:"RFPIAttachedTo,omitempty"`
		SoftwareVersion                         string `json:"SoftwareVersion,omitempty"`
		Status                                  string `json:"Status,omitempty"`
		SubscriptionTime                        string `json:"SubscriptionTime,omitempty"`
		EMCforSUOTA                             int    `json:"EMCforSUOTA,omitempty"`
		SoftwareUpgrade                         bool   `json:"SoftwareUpgrade,omitempty"`
	} `json:"X_SAGEMCOM_DECT_PP,omitempty"`
	XSagemcomDectusb struct {
		Status             string `json:"Status,omitempty"`
		SubscriptionEnable string `json:"SubscriptionEnable,omitempty"`
		CurrentNbPP        int    `json:"CurrentNbPP,omitempty"`
		Enable             bool   `json:"Enable,omitempty"`
	} `json:"X_SAGEMCOM_DECTUSB,omitempty"`
	XSagemcomDectFp struct {
		EepromVersion          string `json:"EepromVersion,omitempty"`
		EncryptionType         string `json:"EncryptionType,omitempty"`
		ErrorStatus            string `json:"ErrorStatus,omitempty"`
		FirmwareVersion        string `json:"FirmwareVersion,omitempty"`
		HardwareVersion        string `json:"HardwareVersion,omitempty"`
		Pin                    string `json:"PIN,omitempty"`
		Rfpi                   string `json:"RFPI,omitempty"`
		RFPowerControl         string `json:"RFPowerControl,omitempty"`
		Standard               string `json:"Standard,omitempty"`
		Status                 string `json:"Status,omitempty"`
		SubscriptionEnable     string `json:"SubscriptionEnable,omitempty"`
		CurrentNbPP            int    `json:"CurrentNbPP,omitempty"`
		FUPercent              int    `json:"FUPercent,omitempty"`
		MaxSupportedPP         int    `json:"MaxSupportedPP,omitempty"`
		SubscriptionTimeout    int    `json:"SubscriptionTimeout,omitempty"`
		CipheringEnable        bool   `json:"CipheringEnable,omitempty"`
		ClockMastered          bool   `json:"ClockMastered,omitempty"`
		Enable                 bool   `json:"Enable,omitempty"`
		InternalListMngtEnable bool   `json:"InternalListMngtEnable,omitempty"`
		NEMOEnable             bool   `json:"NEMOEnable,omitempty"`
		RepeaterSupportEnabled bool   `json:"RepeaterSupportEnabled,omitempty"`
		Reset                  bool   `json:"Reset,omitempty"`
	} `json:"X_SAGEMCOM_DECT_FP,omitempty"`
	XSagemcomFxs struct {
		ReceiveGain            int  `json:"ReceiveGain,omitempty"`
		TransmitGain           int  `json:"TransmitGain,omitempty"`
		CallerIDDateTimeEnable bool `json:"CallerIdDateTimeEnable,omitempty"`
		EchoCancellationEnable bool `json:"EchoCancellationEnable,omitempty"`
	} `json:"X_SAGEMCOM_FXS,omitempty"`
	CallingFeatures struct {
		CallWaitingTimeout        int  `json:"CallWaitingTimeout,omitempty"`
		CallTransferEnable        bool `json:"CallTransferEnable,omitempty"`
		CallWaitingEnable         bool `json:"CallWaitingEnable,omitempty"`
		CallingFeatureEnable      bool `json:"CallingFeatureEnable,omitempty"`
		DoubleCallEnable          bool `json:"DoubleCallEnable,omitempty"`
		LocalAnnouncementEnable   bool `json:"LocalAnnouncementEnable,omitempty"`
		MWIEnable                 bool `json:"MWIEnable,omitempty"`
		XSAGEMCOMConferenceEnable bool `json:"X_SAGEMCOM_ConferenceEnable,omitempty"`
		XSAGEMCOMVMWIEnable       bool `json:"X_SAGEMCOM_VMWIEnable,omitempty"`
	} `json:"CallingFeatures,omitempty"`
	InterfaceID     int  `json:"InterfaceID,omitempty"`
	UID             int  `json:"uid,omitempty"`
	FlashhookEnable bool `json:"FlashhookEnable,omitempty"`
	ForceDTMFInband bool `json:"ForceDTMFInband,omitempty"`
}

type storageServices struct {
	NetInfo struct {
		DomainName string `json:"DomainName,omitempty"`
		HostName   string `json:"HostName,omitempty"`
	} `json:"NetInfo,omitempty"`
	DefaultLogicalVolumesName string `json:"DefaultLogicalVolumesName,omitempty"`
	Capabilities              struct {
		SupportedFileSystemTypes  string `json:"SupportedFileSystemTypes,omitempty"`
		SupportedNetworkProtocols string `json:"SupportedNetworkProtocols,omitempty"`
		SupportedRaidTypes        string `json:"SupportedRaidTypes,omitempty"`
		FTPCapable                bool   `json:"FTPCapable,omitempty"`
		HTTPCapable               bool   `json:"HTTPCapable,omitempty"`
		HTTPSCapable              bool   `json:"HTTPSCapable,omitempty"`
		HTTPWritable              bool   `json:"HTTPWritable,omitempty"`
		SFTPCapable               bool   `json:"SFTPCapable,omitempty"`
		VolumeEncryptionCapable   bool   `json:"VolumeEncryptionCapable,omitempty"`
	} `json:"Capabilities,omitempty"`
	UserAccounts    []any `json:"UserAccounts,omitempty"`
	LogicalVolumes  []any `json:"LogicalVolumes,omitempty"`
	PhysicalMediums []any `json:"PhysicalMediums,omitempty"`
	StorageArrays   []any `json:"StorageArrays,omitempty"`
	UserGroups      []any `json:"UserGroups,omitempty"`
	Printers        struct {
		PrinterDevices []any `json:"PrinterDevices,omitempty"`
		Enable         bool  `json:"Enable,omitempty"`
	} `json:"Printers,omitempty"`
	HTTPServer struct {
		Status             string `json:"Status,omitempty"`
		IdleTime           int    `json:"IdleTime,omitempty"`
		MaxNumUsers        int    `json:"MaxNumUsers,omitempty"`
		PortNumber         int    `json:"PortNumber,omitempty"`
		AuthenticationReq  bool   `json:"AuthenticationReq,omitempty"`
		Enable             bool   `json:"Enable,omitempty"`
		HTTPWritingEnabled bool   `json:"HTTPWritingEnabled,omitempty"`
	} `json:"HTTPServer,omitempty"`
	HTTPSServer struct {
		Status             string `json:"Status,omitempty"`
		IdleTime           int    `json:"IdleTime,omitempty"`
		MaxNumUsers        int    `json:"MaxNumUsers,omitempty"`
		PortNumber         int    `json:"PortNumber,omitempty"`
		AuthenticationReq  bool   `json:"AuthenticationReq,omitempty"`
		Enable             bool   `json:"Enable,omitempty"`
		HTTPWritingEnabled bool   `json:"HTTPWritingEnabled,omitempty"`
	} `json:"HTTPSServer,omitempty"`
	SFTPServer struct {
		Status      string `json:"Status,omitempty"`
		IdleTime    int    `json:"IdleTime,omitempty"`
		MaxNumUsers int    `json:"MaxNumUsers,omitempty"`
		PortNumber  int    `json:"PortNumber,omitempty"`
		Enable      bool   `json:"Enable,omitempty"`
	} `json:"SFTPServer,omitempty"`
	FTPServer struct {
		Status        string `json:"Status,omitempty"`
		AnonymousUser struct {
			StartingFolder string `json:"StartingFolder,omitempty"`
			Enable         bool   `json:"Enable,omitempty"`
			ReadOnlyAccess bool   `json:"ReadOnlyAccess,omitempty"`
		} `json:"AnonymousUser,omitempty"`
		IdleTime    int  `json:"IdleTime,omitempty"`
		MaxNumUsers int  `json:"MaxNumUsers,omitempty"`
		PortNumber  int  `json:"PortNumber,omitempty"`
		Enable      bool `json:"Enable,omitempty"`
	} `json:"FTPServer,omitempty"`
	UID           int `json:"uid,omitempty"`
	NetworkServer struct {
		AFPEnable              bool `json:"AFPEnable,omitempty"`
		NFSEnable              bool `json:"NFSEnable,omitempty"`
		NetworkProtocolAuthReq bool `json:"NetworkProtocolAuthReq,omitempty"`
		SMBEnable              bool `json:"SMBEnable,omitempty"`
	} `json:"NetworkServer,omitempty"`
	Enable bool `json:"Enable,omitempty"`
}

type upnp struct {
	Description struct {
		DeviceDescription []any `json:"DeviceDescription,omitempty"`
		DeviceInstance    []any `json:"DeviceInstance,omitempty"`
		ServiceInstance   []any `json:"ServiceInstance,omitempty"`
	} `json:"Description,omitempty"`
	Discovery struct {
		Devices []struct {
			FriendlyName string `json:"FriendlyName,omitempty"`
			Host         string `json:"Host,omitempty"`
			LastUpdate   string `json:"LastUpdate,omitempty"`
			Location     string `json:"Location,omitempty"`
			Manufacturer string `json:"Manufacturer,omitempty"`
			MediaType    string `json:"MediaType,omitempty"`
			ModelName    string `json:"ModelName,omitempty"`
			Server       string `json:"Server,omitempty"`
			Status       string `json:"Status,omitempty"`
			Usn          string `json:"USN,omitempty"`
			UUID         string `json:"UUID,omitempty"`
			UserAgent    string `json:"UserAgent,omitempty"`
			LeaseTime    int    `json:"LeaseTime,omitempty"`
			Port         int    `json:"Port,omitempty"`
			UID          int    `json:"uid,omitempty"`
		} `json:"Devices,omitempty"`
		RootDevices []struct {
			Host       string `json:"Host,omitempty"`
			LastUpdate string `json:"LastUpdate,omitempty"`
			Location   string `json:"Location,omitempty"`
			Server     string `json:"Server,omitempty"`
			Status     string `json:"Status,omitempty"`
			Usn        string `json:"USN,omitempty"`
			UUID       string `json:"UUID,omitempty"`
			UserAgent  string `json:"UserAgent,omitempty"`
			LeaseTime  int    `json:"LeaseTime,omitempty"`
			Port       int    `json:"Port,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"RootDevices,omitempty"`
		Services []struct {
			Host         string `json:"Host,omitempty"`
			LastUpdate   string `json:"LastUpdate,omitempty"`
			Location     string `json:"Location,omitempty"`
			ParentDevice string `json:"ParentDevice,omitempty"`
			Server       string `json:"Server,omitempty"`
			Status       string `json:"Status,omitempty"`
			Usn          string `json:"USN,omitempty"`
			UserAgent    string `json:"UserAgent,omitempty"`
			LeaseTime    int    `json:"LeaseTime,omitempty"`
			Port         int    `json:"Port,omitempty"`
			UID          int    `json:"uid,omitempty"`
		} `json:"Services,omitempty"`
	} `json:"Discovery,omitempty"`
	Settings upnpSettings `json:"Settings,omitempty"`
	Device   struct {
		Capabilities struct {
			UPnPArchitecture         int `json:"UPnPArchitecture,omitempty"`
			UPnPArchitectureMinorVer int `json:"UPnPArchitectureMinorVer,omitempty"`
			UPnPBasicDevice          int `json:"UPnPBasicDevice,omitempty"`
			UPnPDMBasicMgmt          int `json:"UPnPDMBasicMgmt,omitempty"`
			UPnPDMConfigurationMgmt  int `json:"UPnPDMConfigurationMgmt,omitempty"`
			UPnPDMSoftwareMgmt       int `json:"UPnPDMSoftwareMgmt,omitempty"`
			UPnPIGD                  int `json:"UPnPIGD,omitempty"`
			UPnPMediaRenderer        int `json:"UPnPMediaRenderer,omitempty"`
			UPnPMediaServer          int `json:"UPnPMediaServer,omitempty"`
			UPnPQoSDevice            int `json:"UPnPQoSDevice,omitempty"`
			UPnPQoSPolicyHolder      int `json:"UPnPQoSPolicyHolder,omitempty"`
			UPnPWLANAccessPoint      int `json:"UPnPWLANAccessPoint,omitempty"`
		} `json:"Capabilities,omitempty"`
		Services struct {
			UPnPIGD struct {
				RulesAutoCleanEnable bool `json:"RulesAutoCleanEnable,omitempty"`
			} `json:"UPnPIGD,omitempty"`
		} `json:"Services,omitempty"`
		UPnPDMBasicMgmt         bool `json:"UPnPDMBasicMgmt,omitempty"`
		UPnPDMConfigurationMgmt bool `json:"UPnPDMConfigurationMgmt,omitempty"`
		UPnPDMSoftwareMgmt      bool `json:"UPnPDMSoftwareMgmt,omitempty"`
		UPnPIGD                 bool `json:"UPnPIGD,omitempty"`
		UPnPMediaRenderer       bool `json:"UPnPMediaRenderer,omitempty"`
		UPnPMediaServer         bool `json:"UPnPMediaServer,omitempty"`
		UPnPQoSDevice           bool `json:"UPnPQoSDevice,omitempty"`
		UPnPQoSPolicyHolder     bool `json:"UPnPQoSPolicyHolder,omitempty"`
		UPnPWLANAccessPoint     bool `json:"UPnPWLANAccessPoint,omitempty"`
		Enable                  bool `json:"Enable,omitempty"`
	} `json:"Device,omitempty"`
}

type upnpSettings struct {
	Instance        string `json:"Instance,omitempty"`
	LanInterface    string `json:"LanInterface,omitempty"`
	UPnPMediaServer struct {
		AccessPwd                    string `json:"AccessPwd,omitempty"`
		AccessUser                   string `json:"AccessUser,omitempty"`
		AdaptCase                    string `json:"AdaptCase,omitempty"`
		Aggmode                      string `json:"Aggmode,omitempty"`
		AllName                      string `json:"AllName,omitempty"`
		AllPictures                  string `json:"AllPictures,omitempty"`
		AllRadio                     string `json:"AllRadio,omitempty"`
		AllTracks                    string `json:"AllTracks,omitempty"`
		AllVideos                    string `json:"AllVideos,omitempty"`
		AutoTree                     string `json:"AutoTree,omitempty"`
		CacheMaxSize                 string `json:"CacheMaxSize,omitempty"`
		ContentDir                   string `json:"ContentDir,omitempty"`
		DBDir                        string `json:"DbDir,omitempty"`
		FriendlyName                 string `json:"FriendlyName,omitempty"`
		InternetRadio                string `json:"InternetRadio,omitempty"`
		Language                     string `json:"Language,omitempty"`
		MaxCount                     string `json:"MaxCount,omitempty"`
		MaxMedia                     string `json:"MaxMedia,omitempty"`
		MaxMem                       string `json:"MaxMem,omitempty"`
		PlaylistLastPlayed           string `json:"PlaylistLastPlayed,omitempty"`
		PlaylistMostPlayed           string `json:"PlaylistMostPlayed,omitempty"`
		PlaylistNumEntries           string `json:"PlaylistNumEntries,omitempty"`
		Playlists                    string `json:"Playlists,omitempty"`
		PresentationURL              string `json:"PresentationUrl,omitempty"`
		RootFolder                   string `json:"RootFolder,omitempty"`
		RootMusic                    string `json:"RootMusic,omitempty"`
		RootPicture                  string `json:"RootPicture,omitempty"`
		RootVideo                    string `json:"RootVideo,omitempty"`
		SSDPBeatTime                 string `json:"SSDPBeatTime,omitempty"`
		TagsPicture                  string `json:"TagsPicture,omitempty"`
		UPnPMediaServerVersionNumber string `json:"UPnPMediaServerVersionNumber,omitempty"`
		UploadEnabled                string `json:"UploadEnabled,omitempty"`
		Verbose                      string `json:"Verbose,omitempty"`
		FolderNodes                  []struct {
			Attributes string `json:"Attributes,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"FolderNodes,omitempty"`
		MusicNodes []struct {
			Attributes string `json:"Attributes,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"MusicNodes,omitempty"`
		PictureNodes []struct {
			Attributes string `json:"Attributes,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"PictureNodes,omitempty"`
		VideoNodes []struct {
			Attributes string `json:"Attributes,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"VideoNodes,omitempty"`
		UPnPMediaServerPort int  `json:"UPnPMediaServerPort,omitempty"`
		Aggregation         bool `json:"Aggregation,omitempty"`
		UPnPNMCServer       bool `json:"UPnPNMCServer,omitempty"`
	} `json:"UPnPMediaServer,omitempty"`
	UPnPIGD struct {
		AccessProvider         string `json:"AccessProvider,omitempty"`
		DebugLevel             string `json:"DebugLevel,omitempty"`
		IGDRelease             string `json:"IGDRelease,omitempty"`
		Layer3ForwardingEnable string `json:"Layer3ForwardingEnable,omitempty"`
		InternetGatewayDevice  struct {
			FriendlyName     string `json:"FriendlyName,omitempty"`
			Manufacturer     string `json:"Manufacturer,omitempty"`
			ManufacturerURL  string `json:"ManufacturerURL,omitempty"`
			ModelDescription string `json:"ModelDescription,omitempty"`
			ModelName        string `json:"ModelName,omitempty"`
			ModelNumber      string `json:"ModelNumber,omitempty"`
			ModelURL         string `json:"ModelURL,omitempty"`
			PresentationURL  string `json:"PresentationURL,omitempty"`
			SerialNumber     string `json:"SerialNumber,omitempty"`
			Upc              string `json:"UPC,omitempty"`
		} `json:"InternetGatewayDevice,omitempty"`
		PnPX struct {
			CompatibleID       string `json:"CompatibleId,omitempty"`
			DfDeviceCategory   string `json:"DfDeviceCategory,omitempty"`
			Did                string `json:"Did,omitempty"`
			PnpxDeviceCategory string `json:"PnpxDeviceCategory,omitempty"`
			Rid                string `json:"Rid,omitempty"`
			Sid                string `json:"Sid,omitempty"`
			Vid                string `json:"Vid,omitempty"`
			Enable             bool   `json:"Enable,omitempty"`
		} `json:"PnPX,omitempty"`
		WANConnectionDevice struct {
			FriendlyName     string `json:"FriendlyName,omitempty"`
			Manufacturer     string `json:"Manufacturer,omitempty"`
			ManufacturerURL  string `json:"ManufacturerURL,omitempty"`
			ModelDescription string `json:"ModelDescription,omitempty"`
			ModelName        string `json:"ModelName,omitempty"`
			ModelNumber      string `json:"ModelNumber,omitempty"`
			ModelURL         string `json:"ModelURL,omitempty"`
			PresentationURL  string `json:"PresentationURL,omitempty"`
			SerialNumber     string `json:"SerialNumber,omitempty"`
			Upc              string `json:"UPC,omitempty"`
		} `json:"WANConnectionDevice,omitempty"`
		WANDevice struct {
			FriendlyName     string `json:"FriendlyName,omitempty"`
			Manufacturer     string `json:"Manufacturer,omitempty"`
			ManufacturerURL  string `json:"ManufacturerURL,omitempty"`
			ModelDescription string `json:"ModelDescription,omitempty"`
			ModelName        string `json:"ModelName,omitempty"`
			ModelNumber      string `json:"ModelNumber,omitempty"`
			ModelURL         string `json:"ModelURL,omitempty"`
			PresentationURL  string `json:"PresentationURL,omitempty"`
			SerialNumber     string `json:"SerialNumber,omitempty"`
			Upc              string `json:"UPC,omitempty"`
		} `json:"WANDevice,omitempty"`
		WanInterfaces []struct {
			DefaultName string `json:"DefaultName,omitempty"`
			DefaultType string `json:"DefaultType,omitempty"`
			Interface   string `json:"Interface,omitempty"`
			UID         int    `json:"uid,omitempty"`
			Enable      bool   `json:"Enable,omitempty"`
			EventEnable bool   `json:"EventEnable,omitempty"`
		} `json:"WanInterfaces,omitempty"`
		AdvertisementInterval int  `json:"AdvertisementInterval,omitempty"`
		AdvertisementTTL      int  `json:"AdvertisementTTL,omitempty"`
		DefaultDuration       int  `json:"DefaultDuration,omitempty"`
		DefaultHTTPSPort      int  `json:"DefaultHttpsPort,omitempty"`
		MaxRulesNumber        int  `json:"MaxRulesNumber,omitempty"`
		AuthorizationEnable   bool `json:"AuthorizationEnable,omitempty"`
		WithIcon              bool `json:"WithIcon,omitempty"`
	} `json:"UPnPIGD,omitempty"`
	UPnP struct {
		TimeoutPolling int `json:"TimeoutPolling,omitempty"`
	} `json:"UPnP,omitempty"`
	ExtendedUPnPSecurity bool `json:"ExtendedUPnPSecurity,omitempty"`
}

type Device struct {
	ARP         struct{} `json:"ARP,omitempty"`
	GatewayInfo struct {
		ManufacturerOUI string `json:"ManufacturerOUI,omitempty"`
		ProductClass    string `json:"ProductClass,omitempty"`
	} `json:"GatewayInfo,omitempty"`
	SelfTestDiagnostics struct {
		DiagnosticsState string `json:"DiagnosticsState,omitempty"`
		Results          string `json:"Results,omitempty"`
	} `json:"SelfTestDiagnostics,omitempty"`
	RootDataModelVersion string `json:"RootDataModelVersion,omitempty"`
	DeviceSummary        string `json:"DeviceSummary,omitempty"`
	LANConfigSecurity    struct {
		ConfigPassword string `json:"ConfigPassword,omitempty"`
	} `json:"LANConfigSecurity,omitempty"`
	RestoreInfo struct {
		FileFieldName  string `json:"FileFieldName,omitempty"`
		LastRestore    string `json:"LastRestore,omitempty"`
		URLKOFieldName string `json:"UrlKOFieldName,omitempty"`
		URLOKFieldName string `json:"UrlOKFieldName,omitempty"`
		URLRestore     string `json:"UrlRestore,omitempty"`
		BackupInfo     struct {
			LastDailyBackup   string `json:"LastDailyBackup,omitempty"`
			LastManualBackup  string `json:"LastManualBackup,omitempty"`
			LastMonthlyBackup string `json:"LastMonthlyBackup,omitempty"`
			LastWeeklyBackup  string `json:"LastWeeklyBackup,omitempty"`
		} `json:"BackupInfo,omitempty"`
		AvailableBackups []any `json:"AvailableBackups,omitempty"`
	} `json:"RestoreInfo,omitempty"`
	DLNA struct {
		Capabilities struct {
			AVClassProfileID         string `json:"AVClassProfileID,omitempty"`
			AudioClassProfileID      string `json:"AudioClassProfileID,omitempty"`
			DeviceCapability         string `json:"DeviceCapability,omitempty"`
			HIDDeviceClass           string `json:"HIDDeviceClass,omitempty"`
			HNDDeviceClass           string `json:"HNDDeviceClass,omitempty"`
			ImageClassProfileIDs     string `json:"ImageClassProfileIDs,omitempty"`
			MediaCollectionProfileID string `json:"MediaCollectionProfileID,omitempty"`
			PrinterClassProfileID    string `json:"PrinterClassProfileID,omitempty"`
		} `json:"Capabilities,omitempty"`
		Device struct {
			Enable bool `json:"Enable,omitempty"`
		} `json:"Device,omitempty"`
	} `json:"DLNA,omitempty"`
	GRE struct {
		Filters []any `json:"Filters,omitempty"`
		Tunnels []any `json:"Tunnels,omitempty"`
		Vlans   []any `json:"Vlans,omitempty"`
	} `json:"GRE,omitempty"`
	ISMv2 struct {
		DeviceInets []struct {
			Alias     string `json:"Alias,omitempty"`
			Interface string `json:"Interface,omitempty"`
			Name      string `json:"Name,omitempty"`
			TLS       struct {
				PKIClient string `json:"PKIClient,omitempty"`
				PKIServer string `json:"PKIServer,omitempty"`
				Enable    bool   `json:"Enable,omitempty"`
			} `json:"TLS,omitempty"`
			Dscp                 int  `json:"DSCP,omitempty"`
			PortListen           int  `json:"PortListen,omitempty"`
			PortNotice           int  `json:"PortNotice,omitempty"`
			TimerNoticeCheckRecv int  `json:"TimerNoticeCheckRecv,omitempty"`
			TimerNoticeSend      int  `json:"TimerNoticeSend,omitempty"`
			UID                  int  `json:"uid,omitempty"`
			Enable               bool `json:"Enable,omitempty"`
			Start                bool `json:"Start,omitempty"`
		} `json:"DeviceInets,omitempty"`
		PKIClients []any `json:"PKIClients,omitempty"`
		PKIServers []any `json:"PKIServers,omitempty"`
	} `json:"ISMv2,omitempty"`
	UserAccounts struct {
		LANInterface string `json:"LANInterface,omitempty"`
		WANInterface string `json:"WANInterface,omitempty"`
		MNGInterface string `json:"MNGInterface,omitempty"`
		Users        []struct {
			Address           string `json:"Address,omitempty"`
			Alias             string `json:"Alias,omitempty"`
			Category          string `json:"Category,omitempty"`
			City              string `json:"City,omitempty"`
			ClearTextPassword string `json:"ClearTextPassword,omitempty"`
			Company           string `json:"Company,omitempty"`
			Country           string `json:"Country,omitempty"`
			Email             string `json:"Email,omitempty"`
			FirstName         string `json:"FirstName,omitempty"`
			Language          string `json:"Language,omitempty"`
			LastName          string `json:"LastName,omitempty"`
			Login             string `json:"Login,omitempty"`
			MobilePhoneNumber string `json:"MobilePhoneNumber,omitempty"`
			Password          string `json:"Password,omitempty"`
			Role              string `json:"Role,omitempty"`
			SecretAnswer      string `json:"SecretAnswer,omitempty"`
			SecretQuery       string `json:"SecretQuery,omitempty"`
			Zip               string `json:"ZIP,omitempty"`
			CurrentSessions   []struct {
				ConnectionType  string `json:"ConnectionType,omitempty"`
				InterfaceType   string `json:"InterfaceType,omitempty"`
				LastRequestDate string `json:"LastRequestDate,omitempty"`
				LocalAddress    string `json:"LocalAddress,omitempty"`
				LoginDate       string `json:"LoginDate,omitempty"`
				RemoteAddress   string `json:"RemoteAddress,omitempty"`
				Service         string `json:"Service,omitempty"`
				Status          string `json:"Status,omitempty"`
				LocalPort       int    `json:"LocalPort,omitempty"`
				RemotePort      int    `json:"RemotePort,omitempty"`
				RequestCount    int    `json:"RequestCount,omitempty"`
				SessionID       int    `json:"SessionId,omitempty"`
				Timeout         int    `json:"Timeout,omitempty"`
				UID             int    `json:"uid,omitempty"`
				HostExclusive   bool   `json:"HostExclusive,omitempty"`
			} `json:"CurrentSessions,omitempty"`
			PhoneNumbers               []any `json:"PhoneNumbers,omitempty"`
			MaxSessionCount            int   `json:"MaxSessionCount,omitempty"`
			UID                        int   `json:"uid,omitempty"`
			BasicAuthenticationEnabled bool  `json:"BasicAuthenticationEnabled,omitempty"`
			ConsoleAccess              bool  `json:"ConsoleAccess,omitempty"`
			CurrentlyRemoteAccess      bool  `json:"CurrentlyRemoteAccess,omitempty"`
			Enable                     bool  `json:"Enable,omitempty"`
			ForcePasswordChange        bool  `json:"ForcePasswordChange,omitempty"`
			LocalAccess                bool  `json:"LocalAccess,omitempty"`
			OwnPass                    bool  `json:"OwnPass,omitempty"`
		} `json:"Users,omitempty"`
	} `json:"UserAccounts,omitempty"`
	WebAccesses struct {
		PortTrigger    []any `json:"PortTrigger,omitempty"`
		WebRestriction []any `json:"WebRestriction,omitempty"`
	} `json:"WebAccesses,omitempty"`
	PPP       ppp `json:"PPP,omitempty"`
	Tunneling struct {
		TunnelsL2 []any `json:"TunnelsL2,omitempty"`
	} `json:"Tunneling,omitempty"`
	Optical struct {
		Interfaces []OpticalInterface `json:"Interfaces,omitempty"`
		G988       struct {
			GponState       string `json:"GponState,omitempty"`
			OnuMode         string `json:"OnuMode,omitempty"`
			RegID           string `json:"RegId,omitempty"`
			Software0UbiDev string `json:"Software0UbiDev,omitempty"`
			Software1UbiDev string `json:"Software1UbiDev,omitempty"`
			Logging         struct {
				Destination string `json:"Destination,omitempty"`
				Level       string `json:"Level,omitempty"`
			} `json:"Logging,omitempty"`
			General struct {
				OltG struct {
					EquipmentID string `json:"EquipmentId,omitempty"`
					OltVendorID string `json:"OltVendorId,omitempty"`
					Version     string `json:"Version,omitempty"`
				} `json:"OltG,omitempty"`
			} `json:"General,omitempty"`
			EquipmentManagement struct {
				Onu2G struct {
					EquipmentID       string `json:"EquipmentId,omitempty"`
					VendorProductCode int    `json:"VendorProductCode,omitempty"`
				} `json:"Onu2G,omitempty"`
				OnuG struct {
					SerialNumber            string `json:"SerialNumber,omitempty"`
					VendorID                string `json:"VendorId,omitempty"`
					Version                 string `json:"Version,omitempty"`
					TrafficManagementOption int    `json:"TrafficManagementOption,omitempty"`
				} `json:"OnuG,omitempty"`
				SoftwareImages []struct {
					Version         string `json:"Version,omitempty"`
					ManagedEntityID int    `json:"ManagedEntityId,omitempty"`
					UID             int    `json:"uid,omitempty"`
					IsActive        bool   `json:"IsActive,omitempty"`
					IsCommitted     bool   `json:"IsCommitted,omitempty"`
					IsValid         bool   `json:"IsValid,omitempty"`
				} `json:"SoftwareImages,omitempty"`
			} `json:"EquipmentManagement,omitempty"`
			OperatorConf bool `json:"OperatorConf,omitempty"`
			QosModeRG    bool `json:"QosModeRG,omitempty"`
			Debug        bool `json:"Debug,omitempty"`
		} `json:"G988,omitempty"`
	} `json:"Optical,omitempty"`
	Time struct {
		CurrentLocalTime      string `json:"CurrentLocalTime,omitempty"`
		DaylightSavingTime    string `json:"DaylightSavingTime,omitempty"`
		Interfaces            string `json:"Interfaces,omitempty"`
		LocalTimeZone         string `json:"LocalTimeZone,omitempty"`
		LocalTimeZoneName     string `json:"LocalTimeZoneName,omitempty"`
		LocalTimeZoneNameReal string `json:"LocalTimeZoneNameReal,omitempty"`
		NTPRetryInterval      string `json:"NTPRetryInterval,omitempty"`
		NTPServer1            string `json:"NTPServer1,omitempty"`
		NTPServer2            string `json:"NTPServer2,omitempty"`
		NTPServer3            string `json:"NTPServer3,omitempty"`
		NTPServer4            string `json:"NTPServer4,omitempty"`
		NTPServer5            string `json:"NTPServer5,omitempty"`
		Status                string `json:"Status,omitempty"`
		NTPSyncInterval       int    `json:"NTPSyncInterval,omitempty"`
		Enable                bool   `json:"Enable,omitempty"`
	} `json:"Time,omitempty"`
	Firewall firewall `json:"Firewall,omitempty"`
	UPA      struct {
		Interfaces  []any `json:"Interfaces,omitempty"`
		Diagnostics struct {
			InterfaceMeasurement struct {
				DiagnosticsState string `json:"DiagnosticsState,omitempty"`
				Interface        string `json:"Interface,omitempty"`
				Measurements     string `json:"Measurements,omitempty"`
				Type             string `json:"Type,omitempty"`
				Port             int    `json:"Port,omitempty"`
				RxGain           int    `json:"RxGain,omitempty"`
			} `json:"InterfaceMeasurement,omitempty"`
		} `json:"Diagnostics,omitempty"`
	} `json:"UPA,omitempty"`
	HomePlug struct {
		LastDetectionDate string `json:"LastDetectionDate,omitempty"`
		NetworkInterfaces string `json:"NetworkInterfaces,omitempty"`
		Status            string `json:"Status,omitempty"`
		Interfaces        []any  `json:"Interfaces,omitempty"`
		Enable            bool   `json:"Enable,omitempty"`
	} `json:"HomePlug,omitempty"`
	USB struct {
		USBHosts struct {
			Hosts []struct {
				Alias                 string `json:"Alias,omitempty"`
				Name                  string `json:"Name,omitempty"`
				Type                  string `json:"Type,omitempty"`
				USBVersion            string `json:"USBVersion,omitempty"`
				Devices               []any  `json:"Devices,omitempty"`
				UID                   int    `json:"uid,omitempty"`
				Enable                bool   `json:"Enable,omitempty"`
				PowerManagementEnable bool   `json:"PowerManagementEnable,omitempty"`
				Reset                 bool   `json:"Reset,omitempty"`
			} `json:"Hosts,omitempty"`
		} `json:"USBHosts,omitempty"`
		Interfaces []any `json:"Interfaces,omitempty"`
		Ports      []struct {
			Alias      string `json:"Alias,omitempty"`
			Name       string `json:"Name,omitempty"`
			Power      string `json:"Power,omitempty"`
			Rate       string `json:"Rate,omitempty"`
			Receptacle string `json:"Receptacle,omitempty"`
			Standard   string `json:"Standard,omitempty"`
			SysfsID    string `json:"SysfsId,omitempty"`
			Type       string `json:"Type,omitempty"`
			UID        int    `json:"uid,omitempty"`
		} `json:"Ports,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"USB,omitempty"`
	NAT               nat `json:"NAT,omitempty"`
	NeighborDiscovery struct {
		InterfaceSettings []struct {
			Alias                   string `json:"Alias,omitempty"`
			Interface               string `json:"Interface,omitempty"`
			Status                  string `json:"Status,omitempty"`
			MaxRtrSolicitations     int    `json:"MaxRtrSolicitations,omitempty"`
			RetransTimer            int    `json:"RetransTimer,omitempty"`
			RtrSolicitationInterval int    `json:"RtrSolicitationInterval,omitempty"`
			UID                     int    `json:"uid,omitempty"`
			NUDEnable               bool   `json:"NUDEnable,omitempty"`
			RSEnable                bool   `json:"RSEnable,omitempty"`
			Enable                  bool   `json:"Enable,omitempty"`
		} `json:"InterfaceSettings,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"NeighborDiscovery,omitempty"`
	RouterAdvertisement struct {
		InterfaceSettings []struct {
			AdvPreferredRouterFlag string `json:"AdvPreferredRouterFlag,omitempty"`
			Alias                  string `json:"Alias,omitempty"`
			Interface              string `json:"Interface,omitempty"`
			ManualPrefixes         string `json:"ManualPrefixes,omitempty"`
			Prefixes               string `json:"Prefixes,omitempty"`
			Status                 string `json:"Status,omitempty"`
			Options                []struct {
				Alias  string `json:"Alias,omitempty"`
				Value  string `json:"Value,omitempty"`
				Tag    int    `json:"Tag,omitempty"`
				UID    int    `json:"uid,omitempty"`
				Enable bool   `json:"Enable,omitempty"`
			} `json:"Options,omitempty"`
			AdvCurHopLimit             int  `json:"AdvCurHopLimit,omitempty"`
			AdvDefaultLifetime         int  `json:"AdvDefaultLifetime,omitempty"`
			AdvLinkMTU                 int  `json:"AdvLinkMTU,omitempty"`
			AdvReachableTime           int  `json:"AdvReachableTime,omitempty"`
			AdvRetransTimer            int  `json:"AdvRetransTimer,omitempty"`
			MaxRtrAdvInterval          int  `json:"MaxRtrAdvInterval,omitempty"`
			MinRtrAdvInterval          int  `json:"MinRtrAdvInterval,omitempty"`
			NeighAdvertisementInterval int  `json:"NeighAdvertisementInterval,omitempty"`
			UID                        int  `json:"uid,omitempty"`
			AdvManagedFlag             bool `json:"AdvManagedFlag,omitempty"`
			AdvMobileAgentFlag         bool `json:"AdvMobileAgentFlag,omitempty"`
			AdvNDProxyFlag             bool `json:"AdvNDProxyFlag,omitempty"`
			AdvOtherConfigFlag         bool `json:"AdvOtherConfigFlag,omitempty"`
			Enable                     bool `json:"Enable,omitempty"`
		} `json:"InterfaceSettings,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"RouterAdvertisement,omitempty"`
	Routing struct {
		RouteInformation struct {
			InterfaceSettings []any `json:"InterfaceSettings,omitempty"`
			Enable            bool  `json:"Enable,omitempty"`
		} `json:"RouteInformation,omitempty"`
		Routers []struct {
			Alias           string `json:"Alias,omitempty"`
			Status          string `json:"Status,omitempty"`
			IPv4Forwardings []struct {
				Alias            string `json:"Alias,omitempty"`
				DestIPAddress    string `json:"DestIPAddress,omitempty"`
				DestSubnetMask   string `json:"DestSubnetMask,omitempty"`
				DeviceName       string `json:"DeviceName,omitempty"`
				GatewayIPAddress string `json:"GatewayIPAddress,omitempty"`
				Interface        string `json:"Interface,omitempty"`
				Origin           string `json:"Origin,omitempty"`
				Source           string `json:"Source,omitempty"`
				Status           string `json:"Status,omitempty"`
				ForwardingMetric int    `json:"ForwardingMetric,omitempty"`
				ForwardingPolicy int    `json:"ForwardingPolicy,omitempty"`
				NbRef            int    `json:"NbRef,omitempty"`
				UID              int    `json:"uid,omitempty"`
				Enable           bool   `json:"Enable,omitempty"`
				StaticRoute      bool   `json:"StaticRoute,omitempty"`
			} `json:"IPv4Forwardings,omitempty"`
			IPv6Forwardings []any `json:"IPv6Forwardings,omitempty"`
			UID             int   `json:"uid,omitempty"`
			DefaultRouter   bool  `json:"DefaultRouter,omitempty"`
			Enable          bool  `json:"Enable,omitempty"`
		} `json:"Routers,omitempty"`
		Rip struct {
			Redistribute                      string `json:"Redistribute,omitempty"`
			SupportedModes                    string `json:"SupportedModes,omitempty"`
			InterfaceSettings                 []any  `json:"InterfaceSettings,omitempty"`
			XSAGEMCOMRIPIPPrefix              []any  `json:"X_SAGEMCOM_RIPIPPrefix,omitempty"`
			XSAGEMCOMAdvertisementInterval    int    `json:"X_SAGEMCOM_AdvertisementInterval,omitempty"`
			XSAGEMCOMRIPNATRoutedSubnetEnable bool   `json:"X_SAGEMCOM_RIPNATRoutedSubnetEnable,omitempty"`
			Enable                            bool   `json:"Enable,omitempty"`
		} `json:"RIP,omitempty"`
	} `json:"Routing,omitempty"`
	Hosts struct {
		STBVendorClassIDList      string `json:"STBVendorClassIDList,omitempty"`
		VAPVendorClassIDList      string `json:"VAPVendorClassIDList,omitempty"`
		WiFiPODSVendorClassIDList string `json:"WiFiPODSVendorClassIDList,omitempty"`
		Hosts                     []Host `json:"Hosts,omitempty"`
		MaxHosts                  int    `json:"MaxHosts,omitempty"`
		SweepARP                  int    `json:"SweepARP,omitempty"`
	} `json:"Hosts,omitempty"`
	PeriodicStatistics struct {
		SampleSets        []any `json:"SampleSets,omitempty"`
		MaxReportSamples  int   `json:"MaxReportSamples,omitempty"`
		MinSampleInterval int   `json:"MinSampleInterval,omitempty"`
	} `json:"PeriodicStatistics,omitempty"`
	DHCPv4          dhcpv4 `json:"DHCPv4,omitempty"`
	DeviceDiscovery struct {
		USBEntity struct {
			Name      string `json:"Name,omitempty"`
			Connected bool   `json:"Connected,omitempty"`
		} `json:"USBEntity,omitempty"`
		AccessPoints []struct {
			Name      string `json:"Name,omitempty"`
			UID       int    `json:"uid,omitempty"`
			Connected bool   `json:"Connected,omitempty"`
		} `json:"AccessPoints,omitempty"`
		DHCPPools  []any `json:"DHCPPools,omitempty"`
		Interfaces []struct {
			Path string `json:"Path,omitempty"`
			UID  int    `json:"uid,omitempty"`
			Arp  bool   `json:"Arp,omitempty"`
		} `json:"Interfaces,omitempty"`
		DeviceIdentification struct {
			DeviceTypes             []any `json:"DeviceTypes,omitempty"`
			DHCPFingerprintDatabase struct {
				Entries    []any `json:"Entries,omitempty"`
				MaxEntries int   `json:"MaxEntries,omitempty"`
			} `json:"DHCPFingerprintDatabase,omitempty"`
		} `j2son:"DeviceIdentification,omitempty"`
		MaxHosts int  `json:"MaxHosts,omitempty"`
		Enable   bool `json:"Enable,omitempty"`
	} `json:"DeviceDiscovery,omitempty"`
	MQTT struct {
		Clients []struct {
			Alias                  string `json:"Alias,omitempty"`
			BrokerAddress          string `json:"BrokerAddress,omitempty"`
			CaFile                 string `json:"CaFile,omitempty"`
			CaPath                 string `json:"CaPath,omitempty"`
			CertFile               string `json:"CertFile,omitempty"`
			ClientID               string `json:"ClientID,omitempty"`
			Interface              string `json:"Interface,omitempty"`
			KeyFile                string `json:"KeyFile,omitempty"`
			Name                   string `json:"Name,omitempty"`
			Password               string `json:"Password,omitempty"`
			ProtocolVersion        string `json:"ProtocolVersion,omitempty"`
			Status                 string `json:"Status,omitempty"`
			SubscriptionFileConfig string `json:"SubscriptionFileConfig,omitempty"`
			TransportProtocol      string `json:"TransportProtocol,omitempty"`
			Username               string `json:"Username,omitempty"`
			WillTopic              string `json:"WillTopic,omitempty"`
			WillValue              string `json:"WillValue,omitempty"`
			Subscriptions          []any  `json:"Subscriptions,omitempty"`
			Stats                  struct {
				BrokerConnectionEstablished string `json:"BrokerConnectionEstablished,omitempty"`
				LastPublishMessageReceived  string `json:"LastPublishMessageReceived,omitempty"`
				LastPublishMessageSent      string `json:"LastPublishMessageSent,omitempty"`
				MQTTMessagesReceived        string `json:"MQTTMessagesReceived,omitempty"`
				MQTTMessagesSent            string `json:"MQTTMessagesSent,omitempty"`
				PublishReceived             string `json:"PublishReceived,omitempty"`
				PublishSent                 string `json:"PublishSent,omitempty"`
				SubscribeSent               string `json:"SubscribeSent,omitempty"`
				UnSubscribeSent             string `json:"UnSubscribeSent,omitempty"`
				ConnectionErrors            int    `json:"ConnectionErrors,omitempty"`
				PublishErrors               int    `json:"PublishErrors,omitempty"`
			} `json:"Stats,omitempty"`
			BrokerPort       int  `json:"BrokerPort,omitempty"`
			ConnectRetryTime int  `json:"ConnectRetryTime,omitempty"`
			KeepAliveTime    int  `json:"KeepAliveTime,omitempty"`
			MessageRetryTime int  `json:"MessageRetryTime,omitempty"`
			WillQoS          int  `json:"WillQoS,omitempty"`
			UID              int  `json:"uid,omitempty"`
			CleanSession     bool `json:"CleanSession,omitempty"`
			Enable           bool `json:"Enable,omitempty"`
			ForceReconnect   bool `json:"ForceReconnect,omitempty"`
			TLSInsecure      bool `json:"TlsInsecure,omitempty"`
			WillEnable       bool `json:"WillEnable,omitempty"`
			WillRetain       bool `json:"WillRetain,omitempty"`
		} `json:"Clients,omitempty"`
		Capabilities struct {
			ProtocolVersionsSupported            string `json:"ProtocolVersionsSupported,omitempty"`
			TransportProtocolSupported           string `json:"TransportProtocolSupported,omitempty"`
			MaxNumberOfBrokerBridgeSubscriptions int    `json:"MaxNumberOfBrokerBridgeSubscriptions,omitempty"`
			MaxNumberOfBrokerBridges             int    `json:"MaxNumberOfBrokerBridges,omitempty"`
			MaxNumberOfClientSubscriptions       int    `json:"MaxNumberOfClientSubscriptions,omitempty"`
		} `json:"Capabilities,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"MQTT,omitempty"`
	Ethernet      ethernet   `json:"Ethernet,omitempty"`
	WiFi          wifi       `json:"WiFi,omitempty"`
	DeviceInfo    DeviceInfo `json:"DeviceInfo,omitempty"`
	Services      services   `json:"Services,omitempty"`
	DNS           dns        `json:"DNS,omitempty"`
	IP            ip         `json:"IP,omitempty"`
	UserInterface struct {
		WarrantyDate       string `json:"WarrantyDate,omitempty"`
		ISPNewsServer      string `json:"ISPNewsServer,omitempty"`
		BackgroundColor    string `json:"BackgroundColor,omitempty"`
		AutoUpdateServer   string `json:"AutoUpdateServer,omitempty"`
		ButtonColor        string `json:"ButtonColor,omitempty"`
		ButtonTextColor    string `json:"ButtonTextColor,omitempty"`
		CurrentLanguage    string `json:"CurrentLanguage,omitempty"`
		ISPHelpDesk        string `json:"ISPHelpDesk,omitempty"`
		ISPHelpPage        string `json:"ISPHelpPage,omitempty"`
		ISPHomePage        string `json:"ISPHomePage,omitempty"`
		ISPLogo            string `json:"ISPLogo,omitempty"`
		ISPMailServer      string `json:"ISPMailServer,omitempty"`
		ISPName            string `json:"ISPName,omitempty"`
		AvailableLanguages string `json:"AvailableLanguages,omitempty"`
		Market             string `json:"Market,omitempty"`
		Password           string `json:"Password,omitempty"`
		TextColor          string `json:"TextColor,omitempty"`
		UserUpdateServer   string `json:"UserUpdateServer,omitempty"`
		Brand              string `json:"Brand,omitempty"`
		RedirectionReason  string `json:"RedirectionReason,omitempty"`
		RouterRedirectURL  string `json:"RouterRedirectURL,omitempty"`
		BackupDatas        []struct {
			Alias string `json:"Alias,omitempty"`
			Tag   string `json:"Tag,omitempty"`
			Value string `json:"Value,omitempty"`
			UID   int    `json:"uid,omitempty"`
		} `json:"BackupDatas,omitempty"`
		HideTables []any `json:"HideTables,omitempty"`
		BaseUrls   []any `json:"baseUrls,omitempty"`
		Httpd      struct {
			Redirection          string `json:"Redirection,omitempty"`
			MaxSessions          int    `json:"MaxSessions,omitempty"`
			SessionTimeout       int    `json:"SessionTimeout,omitempty"`
			HostAttackProtection bool   `json:"HostAttackProtection,omitempty"`
		} `json:"Httpd,omitempty"`
		RemoteAccess struct {
			GeneralCodeRemoteApplication string `json:"GeneralCodeRemoteApplication,omitempty"`
			Protocol                     string `json:"Protocol,omitempty"`
			RemoteAccessHost             string `json:"RemoteAccessHost,omitempty"`
			SupportedProtocols           string `json:"SupportedProtocols,omitempty"`
			Port                         int    `json:"Port,omitempty"`
			RemoteApplicationHTTPSPort   int    `json:"RemoteApplicationHTTPSPort,omitempty"`
			Timeout                      int    `json:"Timeout,omitempty"`
			Enable                       bool   `json:"Enable,omitempty"`
			RemoteApplicationEnable      bool   `json:"RemoteApplicationEnable,omitempty"`
		} `json:"RemoteAccess,omitempty"`
		Screen struct {
			DisplayState string `json:"DisplayState,omitempty"`
			Lines        []struct {
				TextToDisplay string `json:"TextToDisplay,omitempty"`
				UID           int    `json:"uid,omitempty"`
			} `json:"Lines,omitempty"`
			DisplayTime    int  `json:"DisplayTime,omitempty"`
			PixelLeap      int  `json:"PixelLeap,omitempty"`
			Priority       int  `json:"Priority,omitempty"`
			ScrollingSpeed int  `json:"ScrollingSpeed,omitempty"`
			ClearOnOk      bool `json:"ClearOnOk,omitempty"`
		} `json:"Screen,omitempty"`
		LocalDisplay struct {
			DisplayHeight int  `json:"DisplayHeight,omitempty"`
			DisplayWidth  int  `json:"DisplayWidth,omitempty"`
			Height        int  `json:"Height,omitempty"`
			PosX          int  `json:"PosX,omitempty"`
			PosY          int  `json:"PosY,omitempty"`
			Width         int  `json:"Width,omitempty"`
			GuiFlag       bool `json:"GuiFlag,omitempty"`
			Movable       bool `json:"Movable,omitempty"`
			Resizable     bool `json:"Resizable,omitempty"`
		} `json:"LocalDisplay,omitempty"`
		GuiLockTime             int  `json:"GuiLockTime,omitempty"`
		ISPLogoSize             int  `json:"ISPLogoSize,omitempty"`
		LoginRetryNumber        int  `json:"LoginRetryNumber,omitempty"`
		PasswordMinLength       int  `json:"PasswordMinLength,omitempty"`
		PasswordRequired        bool `json:"PasswordRequired,omitempty"`
		PasswordReset           bool `json:"PasswordReset,omitempty"`
		PasswordUserSelectable  bool `json:"PasswordUserSelectable,omitempty"`
		RouterRedirectURLEnable bool `json:"RouterRedirectURLEnable,omitempty"`
		UpgradeAvailable        bool `json:"UpgradeAvailable,omitempty"`
	} `json:"UserInterface,omitempty"`
	UPnP upnp `json:"UPnP,omitempty"`
}

type wifiAccessPoints struct {
	PossibleDataTransmitRates    string `json:"PossibleDataTransmitRates,omitempty"`
	Alias                        string `json:"Alias,omitempty"`
	AuthenticationServiceMode    string `json:"AuthenticationServiceMode,omitempty"`
	Bridge                       string `json:"Bridge,omitempty"`
	IP                           string `json:"Ip,omitempty"`
	OperationalDataTransmitRates string `json:"OperationalDataTransmitRates,omitempty"`
	BasicDataTransmitRates       string `json:"BasicDataTransmitRates,omitempty"`
	ProxyMode                    string `json:"ProxyMode,omitempty"`
	BasicAuthenticationMode      string `json:"BasicAuthenticationMode,omitempty"`
	SSIDReference                string `json:"SSIDReference,omitempty"`
	Status                       string `json:"Status,omitempty"`
	MACFiltering                 struct {
		Mode         string `json:"Mode,omitempty"`
		MACAddresses []any  `json:"MACAddresses,omitempty"`
	} `json:"MACFiltering,omitempty"`
	ACs []struct {
		AccessCategory            string `json:"AccessCategory,omitempty"`
		Alias                     string `json:"Alias,omitempty"`
		OutQLenHistogramIntervals string `json:"OutQLenHistogramIntervals,omitempty"`
		Stats                     struct {
			BytesReceived          string `json:"BytesReceived,omitempty"`
			BytesSent              string `json:"BytesSent,omitempty"`
			OutQLenHistogram       string `json:"OutQLenHistogram,omitempty"`
			PacketsReceived        string `json:"PacketsReceived,omitempty"`
			PacketsSent            string `json:"PacketsSent,omitempty"`
			DiscardPacketsReceived int    `json:"DiscardPacketsReceived,omitempty"`
			DiscardPacketsSent     int    `json:"DiscardPacketsSent,omitempty"`
			ErrorsReceived         int    `json:"ErrorsReceived,omitempty"`
			ErrorsSent             int    `json:"ErrorsSent,omitempty"`
			RetransCount           int    `json:"RetransCount,omitempty"`
		} `json:"Stats,omitempty"`
		Aifsn                          int  `json:"AIFSN,omitempty"`
		AIFSNSta                       int  `json:"AIFSN_sta,omitempty"`
		ECWMax                         int  `json:"ECWMax,omitempty"`
		ECWMaxSta                      int  `json:"ECWMax_sta,omitempty"`
		ECWMin                         int  `json:"ECWMin,omitempty"`
		ECWMinSta                      int  `json:"ECWMin_sta,omitempty"`
		OutQLenHistogramSampleInterval int  `json:"OutQLenHistogramSampleInterval,omitempty"`
		TxOpMax                        int  `json:"TxOpMax,omitempty"`
		TxOpMaxSta                     int  `json:"TxOpMax_sta,omitempty"`
		UID                            int  `json:"uid,omitempty"`
		Acm                            bool `json:"ACM,omitempty"`
		ACMSta                         bool `json:"ACM_sta,omitempty"`
		AckPolicy                      bool `json:"AckPolicy,omitempty"`
		AckPolicySta                   bool `json:"AckPolicy_sta,omitempty"`
	} `json:"ACs,omitempty"`
	AssociatedDevices []struct {
		AssociationTime         string `json:"AssociationTime,omitempty"`
		AssociationsDateTime    string `json:"AssociationsDateTime,omitempty"`
		AuthenticationUsername  string `json:"AuthenticationUsername,omitempty"`
		DeviceType              string `json:"DeviceType,omitempty"`
		DisassociationsDateTime string `json:"DisassociationsDateTime,omitempty"`
		Encryption              string `json:"Encryption,omitempty"`
		IPAddress               string `json:"IPAddress,omitempty"`
		MACAddress              string `json:"MACAddress,omitempty"`
		OperatingStandard       string `json:"OperatingStandard,omitempty"`
		SecurityMode            string `json:"SecurityMode,omitempty"`
		SupportedStandards      string `json:"SupportedStandards,omitempty"`
		Stats                   struct {
			AntennasRssi       string `json:"AntennasRssi,omitempty"`
			BytesReceived      string `json:"BytesReceived,omitempty"`
			BytesSent          string `json:"BytesSent,omitempty"`
			ErrorsReceived     string `json:"ErrorsReceived,omitempty"`
			PacketsReceived    string `json:"PacketsReceived,omitempty"`
			PacketsSent        string `json:"PacketsSent,omitempty"`
			ErrorsSent         int    `json:"ErrorsSent,omitempty"`
			FailedRetransCount int    `json:"FailedRetransCount,omitempty"`
			MultipleRetryCount int    `json:"MultipleRetryCount,omitempty"`
			RetransCount       int    `json:"RetransCount,omitempty"`
			RetryCount         int    `json:"RetryCount,omitempty"`
		} `json:"Stats,omitempty"`
		AssociationCount      int  `json:"AssociationCount,omitempty"`
		AuthenticationCount   int  `json:"AuthenticationCount,omitempty"`
		DeauthenticationCount int  `json:"DeauthenticationCount,omitempty"`
		DisassociationCount   int  `json:"DisassociationCount,omitempty"`
		LastDataDownlinkRate  int  `json:"LastDataDownlinkRate,omitempty"`
		LastDataUplinkRate    int  `json:"LastDataUplinkRate,omitempty"`
		Noise                 int  `json:"Noise,omitempty"`
		Retransmissions       int  `json:"Retransmissions,omitempty"`
		SignalStrength        int  `json:"SignalStrength,omitempty"`
		Uptime                int  `json:"Uptime,omitempty"`
		UID                   int  `json:"uid,omitempty"`
		Active                bool `json:"Active,omitempty"`
		AuthenticationState   bool `json:"AuthenticationState,omitempty"`
		MUSupport             bool `json:"MUSupport,omitempty"`
	} `json:"AssociatedDevices,omitempty"`
	Wps struct {
		ConfigMethodsEnabled   string `json:"ConfigMethodsEnabled,omitempty"`
		ConfigMethodsSupported string `json:"ConfigMethodsSupported,omitempty"`
		DevicePIN              string `json:"DevicePIN,omitempty"`
		EnrolleePIN            string `json:"EnrolleePIN,omitempty"`
		M1AccessControlList    string `json:"M1AccessControlList,omitempty"`
		M1AccessControlRule    string `json:"M1AccessControlRule,omitempty"`
		SecurityModesEnabled   string `json:"SecurityModesEnabled,omitempty"`
		SessionStatus          string `json:"SessionStatus,omitempty"`
		Timeout                int    `json:"Timeout,omitempty"`
		Unconfigured           bool   `json:"Unconfigured,omitempty"`
		Enable                 bool   `json:"Enable,omitempty"`
	} `json:"WPS,omitempty"`
	Security struct {
		ECGroupID                   string `json:"ECGroupID,omitempty"`
		EncryptionModeEnabled       string `json:"EncryptionModeEnabled,omitempty"`
		EncryptionModesSupported    string `json:"EncryptionModesSupported,omitempty"`
		KeyPassphrase               string `json:"KeyPassphrase,omitempty"`
		MFPConfig                   string `json:"MFPConfig,omitempty"`
		ModeEnabled                 string `json:"ModeEnabled,omitempty"`
		ModesSupported              string `json:"ModesSupported,omitempty"`
		PreSharedKey                string `json:"PreSharedKey,omitempty"`
		RadiusSecret                string `json:"RadiusSecret,omitempty"`
		RadiusServerIPAddr          string `json:"RadiusServerIPAddr,omitempty"`
		SAEPassphrase               string `json:"SAEPassphrase,omitempty"`
		SecondaryRadiusSecret       string `json:"SecondaryRadiusSecret,omitempty"`
		SecondaryRadiusServerIPAddr string `json:"SecondaryRadiusServerIPAddr,omitempty"`
		AntiCloggingThreshold       int    `json:"AntiCloggingThreshold,omitempty"`
		RadiusServerPort            int    `json:"RadiusServerPort,omitempty"`
		RekeyingInterval            int    `json:"RekeyingInterval,omitempty"`
		SecondaryRadiusServerPort   int    `json:"SecondaryRadiusServerPort,omitempty"`
		Reset                       bool   `json:"Reset,omitempty"`
	} `json:"Security,omitempty"`
	Accounting struct {
		SecondarySecret       string `json:"SecondarySecret,omitempty"`
		SecondaryServerIPAddr string `json:"SecondaryServerIPAddr,omitempty"`
		Secret                string `json:"Secret,omitempty"`
		ServerIPAddr          string `json:"ServerIPAddr,omitempty"`
		ClientPort            int    `json:"ClientPort,omitempty"`
		InterimInterval       int    `json:"InterimInterval,omitempty"`
		Retries               int    `json:"Retries,omitempty"`
		RetryTimeout          int    `json:"RetryTimeout,omitempty"`
		SecondaryServerPort   int    `json:"SecondaryServerPort,omitempty"`
		ServerPort            int    `json:"ServerPort,omitempty"`
		Enable                bool   `json:"Enable,omitempty"`
	} `json:"Accounting,omitempty"`
	ZeroPacketLost        int `json:"ZeroPacketLost,omitempty"`
	UID                   int `json:"uid,omitempty"`
	RetryLimit            int `json:"RetryLimit,omitempty"`
	MaxAssociatedDevices  int `json:"MaxAssociatedDevices,omitempty"`
	VirtualInterfaceIndex int `json:"VirtualInterfaceIndex,omitempty"`
	RadioMeasurements     struct {
		BeaconRequestActive  bool `json:"BeaconRequestActive,omitempty"`
		BeaconRequestPassive bool `json:"BeaconRequestPassive,omitempty"`
		BeaconRequestTable   bool `json:"BeaconRequestTable,omitempty"`
		LinkMeasurement      bool `json:"LinkMeasurement,omitempty"`
		NeighborReport       bool `json:"NeighborReport,omitempty"`
	} `json:"RadioMeasurements,omitempty"`
	DirectMulticast          bool `json:"DirectMulticast,omitempty"`
	AssociationForbidden     bool `json:"AssociationForbidden,omitempty"`
	Enable                   bool `json:"Enable,omitempty"`
	IsolationEnable          bool `json:"IsolationEnable,omitempty"`
	SSIDAdvertisementEnabled bool `json:"SSIDAdvertisementEnabled,omitempty"`
	UAPSDCapability          bool `json:"UAPSDCapability,omitempty"`
	UAPSDEnable              bool `json:"UAPSDEnable,omitempty"`
	WMMCapability            bool `json:"WMMCapability,omitempty"`
	WMMEnable                bool `json:"WMMEnable,omitempty"`
}

type wifi struct {
	VisionInterface           string `json:"VisionInterface,omitempty"`
	NeighboringWiFiDiagnostic struct {
		DiagnosticsState string `json:"DiagnosticsState,omitempty"`
		Result           []any  `json:"Result,omitempty"`
	} `json:"NeighboringWiFiDiagnostic,omitempty"`
	AccessPoints []wifiAccessPoints `json:"AccessPoints,omitempty"`
	Radios       []Radio            `json:"Radios,omitempty"`
	SSIDs        []SSID             `json:"SSIDs,omitempty"`
	Broadcom     struct {
		DetectedCrash            string `json:"DetectedCrash,omitempty"`
		DongleMemDumpLocalPath   string `json:"DongleMemDumpLocalPath,omitempty"`
		DriverErrorManagement    string `json:"DriverErrorManagement,omitempty"`
		LastCrashSinceBoot       string `json:"LastCrashSinceBoot,omitempty"`
		LastCrashSinceReset      string `json:"LastCrashSinceReset,omitempty"`
		CrashNumberSinceBoot     int    `json:"CrashNumberSinceBoot,omitempty"`
		ReloadNumberBeforeReboot int    `json:"ReloadNumberBeforeReboot,omitempty"`
	} `json:"Broadcom,omitempty"`
	Wms struct {
		BeaconAPs          []any `json:"beaconAPs,omitempty"`
		BeaconReportPeriod int   `json:"BeaconReportPeriod,omitempty"`
		HeaderLogPeriod    int   `json:"HeaderLogPeriod,omitempty"`
		Period             int   `json:"Period,omitempty"`
		Enable             bool  `json:"Enable,omitempty"`
	} `json:"WMS,omitempty"`
	BandSteering struct {
		Status        string `json:"Status,omitempty"`
		Devices       []any  `json:"Devices,omitempty"`
		Interfaces    []any  `json:"Interfaces,omitempty"`
		BsdParameters struct {
			BounceDetection struct {
				Counts     int `json:"Counts,omitempty"`
				DwellTime  int `json:"DwellTime,omitempty"`
				WindowTime int `json:"WindowTime,omitempty"`
			} `json:"BounceDetection,omitempty"`
			AirtimeSlowestLink int  `json:"AirtimeSlowestLink,omitempty"`
			BsdScheme          int  `json:"BsdScheme,omitempty"`
			PhyRate            int  `json:"PhyRate,omitempty"`
			BSSTransition      bool `json:"BSSTransition,omitempty"`
			LegacyBandSteering bool `json:"LegacyBandSteering,omitempty"`
			MessageLevelDebug  bool `json:"MessageLevelDebug,omitempty"`
		} `json:"BsdParameters,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"BandSteering,omitempty"`
	VisionEnable bool `json:"VisionEnable,omitempty"`
}

type DeviceInfo struct {
	BuildDate       time.Time `json:"BuildDate,omitempty"`
	FirstUseDate    time.Time `json:"FirstUseDate,omitempty"`
	BackupTimeStamp time.Time `json:"BackupTimeStamp,omitempty"`
	ProxierInfo     struct {
		ManufacturerOUI string `json:"ManufacturerOUI,omitempty"`
		ProductClass    string `json:"ProductClass,omitempty"`
		ProxyProtocol   string `json:"ProxyProtocol,omitempty"`
		SerialNumber    string `json:"SerialNumber,omitempty"`
	} `json:"ProxierInfo,omitempty"`
	SimpleLogs struct {
		CallLog     string `json:"CallLog,omitempty"`
		FirewallLog string `json:"FirewallLog,omitempty"`
		SystemLog   string `json:"SystemLog,omitempty"`
	} `json:"SimpleLogs,omitempty"`
	ProductClass              string       `json:"ProductClass,omitempty"`
	Country                   string       `json:"Country,omitempty"`
	ManufacturerOUI           string       `json:"ManufacturerOUI,omitempty"`
	SpecVersion               string       `json:"SpecVersion,omitempty"`
	SoftwareVersion           string       `json:"SoftwareVersion,omitempty"`
	AdditionalHardwareVersion string       `json:"AdditionalHardwareVersion,omitempty"`
	CustomerModelName         string       `json:"CustomerModelName,omitempty"`
	Description               string       `json:"Description,omitempty"`
	DeviceCategory            string       `json:"DeviceCategory,omitempty"`
	DeviceLog                 string       `json:"DeviceLog,omitempty"`
	EventLog                  string       `json:"EventLog,omitempty"`
	ExternalFirmwareVersion   string       `json:"ExternalFirmwareVersion,omitempty"`
	RouterName                string       `json:"RouterName,omitempty"`
	BackupSoftwareVersion     string       `json:"BackupSoftwareVersion,omitempty"`
	AdditionalSoftwareVersion string       `json:"AdditionalSoftwareVersion,omitempty"`
	Mode                      string       `json:"Mode,omitempty"`
	GUIAPIVersion             string       `json:"GUIAPIVersion,omitempty"`
	GUIFirmwareVersion        string       `json:"GUIFirmwareVersion,omitempty"`
	HardwareVersion           string       `json:"HardwareVersion,omitempty"`
	InternalFirmwareVersion   string       `json:"InternalFirmwareVersion,omitempty"`
	ProvisioningCode          string       `json:"ProvisioningCode,omitempty"`
	APIVersion                string       `json:"APIVersion,omitempty"`
	MACAddress                string       `json:"MACAddress,omitempty"`
	Manufacturer              string       `json:"Manufacturer,omitempty"`
	Clid                      string       `json:"CLID,omitempty"`
	BootloaderVersion         string       `json:"BootloaderVersion,omitempty"`
	ONTSerialNumber           string       `json:"ONTSerialNumber,omitempty"`
	ModelName                 string       `json:"ModelName,omitempty"`
	ModelNumber               string       `json:"ModelNumber,omitempty"`
	NodesToRestore            string       `json:"NodesToRestore,omitempty"`
	CrashHistory              CrashHistory `json:"CrashHistory,omitempty"`
	VendorLogFiles            []struct {
		Alias           string `json:"Alias,omitempty"`
		DiagnosticState string `json:"DiagnosticState,omitempty"`
		LogData         string `json:"LogData,omitempty"`
		Name            string `json:"Name,omitempty"`
		MaximumSize     int    `json:"MaximumSize,omitempty"`
		UID             int    `json:"uid,omitempty"`
		Persistent      bool   `json:"Persistent,omitempty"`
	} `json:"VendorLogFiles,omitempty"`
	VendorConfigFiles []struct {
		Alias               string `json:"Alias,omitempty"`
		Date                string `json:"Date,omitempty"`
		Description         string `json:"Description,omitempty"`
		Name                string `json:"Name,omitempty"`
		Version             string `json:"Version,omitempty"`
		UID                 int    `json:"uid,omitempty"`
		UseForBackupRestore bool   `json:"UseForBackupRestore,omitempty"`
	} `json:"VendorConfigFiles,omitempty"`
	Locations         []any `json:"Locations,omitempty"`
	NetworkProperties struct {
		TCPImplementation string `json:"TCPImplementation,omitempty"`
		MaxTCPWindowSize  int    `json:"MaxTCPWindowSize,omitempty"`
	} `json:"NetworkProperties,omitempty"`
	UserConfigFiles   []any `json:"UserConfigFiles,omitempty"`
	TemperatureStatus struct {
		TemperatureSensors []struct {
			Alias           string `json:"Alias,omitempty"`
			HighAlarmTime   string `json:"HighAlarmTime,omitempty"`
			LastUpdate      string `json:"LastUpdate,omitempty"`
			LowAlarmTime    string `json:"LowAlarmTime,omitempty"`
			MaxTime         string `json:"MaxTime,omitempty"`
			MinTime         string `json:"MinTime,omitempty"`
			Name            string `json:"Name,omitempty"`
			ResetTime       string `json:"ResetTime,omitempty"`
			Status          string `json:"Status,omitempty"`
			HighAlarmValue  int    `json:"HighAlarmValue,omitempty"`
			LowAlarmValue   int    `json:"LowAlarmValue,omitempty"`
			MaxValue        int    `json:"MaxValue,omitempty"`
			MinValue        int    `json:"MinValue,omitempty"`
			PollingInterval int    `json:"PollingInterval,omitempty"`
			Value           int    `json:"Value,omitempty"`
			UID             int    `json:"uid,omitempty"`
			Enable          bool   `json:"Enable,omitempty"`
			Reset           bool   `json:"Reset,omitempty"`
		} `json:"TemperatureSensors,omitempty"`
	} `json:"TemperatureStatus,omitempty"`
	Processors []struct {
		Alias        string `json:"Alias,omitempty"`
		Architecture string `json:"Architecture,omitempty"`
		UID          int    `json:"uid,omitempty"`
	} `json:"Processors,omitempty"`
	Logging struct {
		LogLevel string `json:"LogLevel,omitempty"`
		Syslog   struct {
			FileStorageLocation string `json:"FileStorageLocation,omitempty"`
			LogStorage          string `json:"LogStorage,omitempty"`
			Destinations        []struct {
				Alias               string `json:"Alias,omitempty"`
				FileStorageLocation string `json:"FileStorageLocation,omitempty"`
				LoggerCategories    string `json:"LoggerCategories,omitempty"`
				Status              string `json:"Status,omitempty"`
				SyslogConfig        string `json:"SyslogConfig,omitempty"`
				LogSize             int    `json:"LogSize,omitempty"`
				SourceIndex         int    `json:"SourceIndex,omitempty"`
				UID                 int    `json:"uid,omitempty"`
				Enable              bool   `json:"Enable,omitempty"`
			} `json:"Destinations,omitempty"`
			Sources []struct {
				Alias              string `json:"Alias,omitempty"`
				FileSourceLocation string `json:"FileSourceLocation,omitempty"`
				Network            struct {
					Protocol string `json:"Protocol,omitempty"`
					Port     int    `json:"Port,omitempty"`
					Enable   bool   `json:"Enable,omitempty"`
				} `json:"Network,omitempty"`
				Enable         bool `json:"Enable,omitempty"`
				InternalSource bool `json:"InternalSource,omitempty"`
				KernelSource   bool `json:"KernelSource,omitempty"`
				UnixStream     bool `json:"UnixStream,omitempty"`
				UID            int  `json:"uid,omitempty"`
			} `json:"Sources,omitempty"`
			DisplayKernelLogs bool `json:"DisplayKernelLogs,omitempty"`
			Enable            bool `json:"Enable,omitempty"`
		} `json:"Syslog,omitempty"`
		ResetLogOper bool `json:"ResetLogOper,omitempty"`
	} `json:"Logging,omitempty"`
	FlashMemoryStatus struct {
		Free  int `json:"Free,omitempty"`
		Total int `json:"Total,omitempty"`
	} `json:"FlashMemoryStatus,omitempty"`
	MemoryStatus struct {
		Free  int `json:"Free,omitempty"`
		Total int `json:"Total,omitempty"`
	} `json:"MemoryStatus,omitempty"`
	ResetStatus               int  `json:"ResetStatus,omitempty"`
	RebootStatus              int  `json:"RebootStatus,omitempty"`
	UpTime                    int  `json:"UpTime,omitempty"`
	UpdateStatus              int  `json:"UpdateStatus,omitempty"`
	RebootCount               int  `json:"RebootCount,omitempty"`
	FlushDeviceLog            bool `json:"FlushDeviceLog,omitempty"`
	ConfigBackupRestoreEnable bool `json:"ConfigBackupRestoreEnable,omitempty"`
	SNMP                      bool `json:"SNMP,omitempty"`
	FirstConnection           bool `json:"FirstConnection,omitempty"`
}

type Radio struct {
	CSADeauth                      string `json:"CSADeauth,omitempty"`
	SplittedOperatingFrequencyBand string `json:"SplittedOperatingFrequencyBand,omitempty"`
	GuardInterval                  string `json:"GuardInterval,omitempty"`
	RegulatoryRegionSubRegion      string `json:"RegulatoryRegionSubRegion,omitempty"`
	InitiateACS                    string `json:"InitiateACS,omitempty"`
	Alias                          string `json:"Alias,omitempty"`
	TxSTBC                         string `json:"TxSTBC,omitempty"`
	TxLDPC                         string `json:"TxLDPC,omitempty"`
	AutoChannelList                string `json:"AutoChannelList,omitempty"`
	TransmitPowerSupported         string `json:"TransmitPowerSupported,omitempty"`
	CCARequest                     string `json:"CCARequest,omitempty"`
	SupportedFrequencyBands        string `json:"SupportedFrequencyBands,omitempty"`
	IfcName                        string `json:"IfcName,omitempty"`
	SupportedChannelBandwidth      string `json:"SupportedChannelBandwidth,omitempty"`
	BasicDataTransmitRates         string `json:"BasicDataTransmitRates,omitempty"`
	StoppedBy                      string `json:"StoppedBy,omitempty"`
	BlackListedChannels            string `json:"BlackListedChannels,omitempty"`
	Status                         string `json:"Status,omitempty"`
	RxSTBC                         string `json:"RxSTBC,omitempty"`
	CCAReport                      string `json:"CCAReport,omitempty"`
	SupportedStandards             string `json:"SupportedStandards,omitempty"`
	Interference                   string `json:"Interference,omitempty"`
	SupportedDataTransmitRates     string `json:"SupportedDataTransmitRates,omitempty"`
	RegulatoryDomain               string `json:"RegulatoryDomain,omitempty"`
	RPIHistogramRequest            string `json:"RPIHistogramRequest,omitempty"`
	RPIHistogramReport             string `json:"RPIHistogramReport,omitempty"`
	LocationDescription            string `json:"LocationDescription,omitempty"`
	PreambleType                   string `json:"PreambleType,omitempty"`
	ChannelsInUse                  string `json:"ChannelsInUse,omitempty"`
	PossibleChannels               string `json:"PossibleChannels,omitempty"`
	DFSChannel                     string `json:"DFSChannel,omitempty"`
	OperationalDataTransmitRates   string `json:"OperationalDataTransmitRates,omitempty"`
	OperatingStandards             string `json:"OperatingStandards,omitempty"`
	DeviceOperationMode            string `json:"DeviceOperationMode,omitempty"`
	OperatingMCSSet                string `json:"OperatingMCSSet,omitempty"`
	OperatingFrequencyBand         string `json:"OperatingFrequencyBand,omitempty"`
	OperatingChannelBandwidth      string `json:"OperatingChannelBandwidth,omitempty"`
	Name                           string `json:"Name,omitempty"`
	ExtensionChannel               string `json:"ExtensionChannel,omitempty"`
	LowerLayers                    string `json:"LowerLayers,omitempty"`
	ChannelHoppingHistory          struct {
		Channels  string `json:"Channels,omitempty"`
		Reason    string `json:"Reason,omitempty"`
		Timestamp string `json:"Timestamp,omitempty"`
		Count     int    `json:"Count,omitempty"`
	} `json:"ChannelHoppingHistory,omitempty"`
	WirelessScan struct {
		ChannelsToTest string `json:"ChannelsToTest,omitempty"`
		State          string `json:"State,omitempty"`
		SSIDs          []any  `json:"SSIDs,omitempty"`
	} `json:"WirelessScan,omitempty"`
	SiteSurvey struct {
		ChannelsToTest string `json:"ChannelsToTest,omitempty"`
		ScanMode       string `json:"ScanMode,omitempty"`
		State          string `json:"State,omitempty"`
		ChannelSurveys []any  `json:"ChannelSurveys,omitempty"`
		MaxDwellTime   int    `json:"MaxDwellTime,omitempty"`
		MinDwellTime   int    `json:"MinDwellTime,omitempty"`
		NbEntries      int    `json:"NbEntries,omitempty"`
		SamplePeriod   int    `json:"SamplePeriod,omitempty"`
	} `json:"SiteSurvey,omitempty"`
	Stats struct {
		Active                 string `json:"Active,omitempty"`
		BKCount                string `json:"BK_count,omitempty"`
		BcnCount               string `json:"Bcn_count,omitempty"`
		BeCount                string `json:"Be_count,omitempty"`
		BytesReceived          string `json:"BytesReceived,omitempty"`
		BytesSent              string `json:"BytesSent,omitempty"`
		CabCount               string `json:"Cab_count,omitempty"`
		PacketsReceived        string `json:"PacketsReceived,omitempty"`
		PacketsSent            string `json:"PacketsSent,omitempty"`
		ViCount                string `json:"Vi_count,omitempty"`
		VoCount                string `json:"Vo_count,omitempty"`
		CollisionsPackets      int    `json:"CollisionsPackets,omitempty"`
		DiscardPacketsReceived int    `json:"DiscardPacketsReceived,omitempty"`
		DiscardPacketsSent     int    `json:"DiscardPacketsSent,omitempty"`
		ErrorsReceived         int    `json:"ErrorsReceived,omitempty"`
		ErrorsSent             int    `json:"ErrorsSent,omitempty"`
		FCSErrorCount          int    `json:"FCSErrorCount,omitempty"`
		InvalidMACCount        int    `json:"InvalidMACCount,omitempty"`
		Noise                  int    `json:"Noise,omitempty"`
		Opertxpower            int    `json:"Opertxpower,omitempty"`
		PLCPErrorCount         int    `json:"PLCPErrorCount,omitempty"`
		PacketsOtherReceived   int    `json:"PacketsOtherReceived,omitempty"`
		SampleCount            int    `json:"SampleCount,omitempty"`
	} `json:"Stats,omitempty"`
	Channel                          int     `json:"Channel,omitempty"`
	RTSThreshold                     int     `json:"RTSThreshold,omitempty"`
	UID                              int     `json:"uid,omitempty"`
	Ampdumpdu                        int     `json:"AMPDUMPDU,omitempty"`
	Amsdu                            int     `json:"AMSDU,omitempty"`
	AutoChannelAcsTriggerVar         int     `json:"AutoChannelAcsTriggerVar,omitempty"`
	AutoChannelLockoutPeriod         int     `json:"AutoChannelLockoutPeriod,omitempty"`
	GreenAPDelay                     int     `json:"GreenAPDelay,omitempty"`
	LastChange                       int     `json:"LastChange,omitempty"`
	LastStatsReset                   int     `json:"LastStatsReset,omitempty"`
	TransmitPowerMax                 float64 `json:"TransmitPowerMax,omitempty"`
	LongRetryLimit                   int     `json:"LongRetryLimit,omitempty"`
	FragmentationThreshold           int     `json:"FragmentationThreshold,omitempty"`
	Mcs                              int     `json:"MCS,omitempty"`
	MaxBitRate                       int64   `json:"MaxBitRate,omitempty"`
	TransmitPower                    float64
	AutoChannelMaxAcs                int `json:"AutoChannelMaxAcs,omitempty"`
	AutoChannelRefreshPeriod         int `json:"AutoChannelRefreshPeriod,omitempty"`
	BeaconPeriod                     int `json:"BeaconPeriod,omitempty"`
	BoardSpecificChipIndex           int `json:"BoardSpecificChipIndex,omitempty"`
	DTIMPeriod                       int `json:"DTIMPeriod,omitempty"`
	RetryLimit                       int `json:"RetryLimit,omitempty"`
	CSACount                         int `json:"CSACount,omitempty"`
	CurrentOperatingChannelBandwidth int64
	RadarDetections                  int  `json:"RadarDetections,omitempty"`
	Ampdu                            int  `json:"AMPDU,omitempty"`
	NewChannelsEnable                bool `json:"NewChannelsEnable,omitempty"`
	ChannelHoppingStatus             bool `json:"ChannelHoppingStatus,omitempty"`
	Enable11Ac2G                     bool `json:"Enable11ac2G,omitempty"`
	CSAEnable                        bool `json:"CSAEnable,omitempty"`
	PacketAggregationEnable          bool `json:"PacketAggregationEnable,omitempty"`
	ResetStats                       bool `json:"ResetStats,omitempty"`
	DLMUMIMOEnabled                  bool `json:"DLMUMIMOEnabled,omitempty"`
	BurstModeEnable                  bool `json:"BurstModeEnable,omitempty"`
	SingleTxCCK                      bool `json:"SingleTxCCK,omitempty"`
	Diversity11B                     bool `json:"Diversity11b,omitempty"`
	DownlinkOFDMAEnable              bool `json:"DownlinkOFDMAEnable,omitempty"`
	AutoChannelTrigger               bool `json:"AutoChannelTrigger,omitempty"`
	AutoChannelSupported             bool `json:"AutoChannelSupported,omitempty"`
	Enable                           bool `json:"Enable,omitempty"`
	GModeProtectionEnabled           bool `json:"gModeProtectionEnabled,omitempty"`
	HybridScanMode                   bool `json:"HybridScanMode,omitempty"`
	FrameBurstEnabled                bool `json:"FrameBurstEnabled,omitempty"`
	GreenAPEnabled                   bool `json:"GreenAPEnabled,omitempty"`
	AutoChannelEnable                bool `json:"AutoChannelEnable,omitempty"`
	IncreasedPowerEnable             bool `json:"IncreasedPowerEnable,omitempty"`
	AdminStatus                      bool `json:"AdminStatus,omitempty"`
	ATFEnable                        bool `json:"ATFEnable,omitempty"`
	HostBasedScbEnable               bool `json:"HostBasedScbEnable,omitempty"`
	IEEE80211HSupported              bool `json:"IEEE80211hSupported,omitempty"`
	TransmitBeamForming              bool `json:"TransmitBeamForming,omitempty"`
	UplinkOFDMAEnable                bool `json:"UplinkOFDMAEnable,omitempty"`
	Upstream                         bool `json:"Upstream,omitempty"`
	VoWEnable                        bool `json:"VoWEnable,omitempty"`
	IEEE80211HEnabled                bool `json:"IEEE80211hEnabled,omitempty"`
	ChannelHoppingEnable             bool `json:"ChannelHoppingEnable,omitempty"`
}

func (r *Radio) UnmarshalJSON(data []byte) error {
	type alias Radio

	aux := &struct {
		*alias
		CurrentOperatingChannelBandwidth string `json:"CurrentOperatingChannelBandwidth"`
		TransmitPower                    int    `json:"TransmitPower"`
	}{
		alias: (*alias)(r),
	}

	if aux.CurrentOperatingChannelBandwidth != "" {
		if strings.HasSuffix(aux.CurrentOperatingChannelBandwidth, "MHz") {
			bw, err := strconv.Atoi(aux.CurrentOperatingChannelBandwidth[:len(aux.CurrentOperatingChannelBandwidth)-3])
			if err != nil {
				return err
			}

			r.CurrentOperatingChannelBandwidth = int64(bw) * 1_000_000
		}
	}

	// Convert the MaxBitRate from Mbps to bps
	r.MaxBitRate = aux.MaxBitRate * 1024 * 1024

	// Convert TransmitPower from a percentage out of 100 to a ratio out of 1
	r.TransmitPower = float64(aux.TransmitPower) / 100

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	return nil
}

type SSID struct {
	Alias       string `json:"Alias,omitempty"`
	Bssid       string `json:"BSSID,omitempty"`
	IfcName     string `json:"IfcName,omitempty"`
	LowerLayers string `json:"LowerLayers,omitempty"`
	MACAddress  string `json:"MACAddress,omitempty"`
	Name        string `json:"Name,omitempty"`
	SSID        string `json:"SSID,omitempty"`
	Status      string `json:"Status,omitempty"`
	StoppedBy   string `json:"StoppedBy,omitempty"`
	Stats       struct {
		ACKFailureCount             int64 `json:"ACKFailureCount"`
		AggregatedPacketCount       int64 `json:"AggregatedPacketCount"`
		BroadcastPacketsReceived    int64 `json:"BroadcastPacketsReceived,string"`
		BroadcastPacketsSent        int64 `json:"BroadcastPacketsSent,string"`
		BytesReceived               int64 `json:"BytesReceived,string"`
		BytesSent                   int64 `json:"BytesSent,string"`
		CollisionsPackets           int64 `json:"CollisionsPackets"`
		DiscardPacketsReceived      int64 `json:"DiscardPacketsReceived"`
		DiscardPacketsSent          int64 `json:"DiscardPacketsSent"`
		ErrorsReceived              int64 `json:"ErrorsReceived"`
		ErrorsSent                  int64 `json:"ErrorsSent"`
		FailedRetransCount          int64 `json:"FailedRetransCount"`
		MulticastPacketsReceived    int64 `json:"MulticastPacketsReceived,string"`
		MulticastPacketsSent        int64 `json:"MulticastPacketsSent,string"`
		MultipleRetryCount          int64 `json:"MultipleRetryCount"`
		PacketsReceived             int64 `json:"PacketsReceived,string"`
		PacketsSent                 int64 `json:"PacketsSent,string"`
		RetransCount                int64 `json:"RetransCount"`
		RetryCount                  int64 `json:"RetryCount"`
		RxRetryCount                int64 `json:"RxRetryCount"`
		UnicastPacketsReceived      int64 `json:"UnicastPacketsReceived,string"`
		UnicastPacketsSent          int64 `json:"UnicastPacketsSent,string"`
		UnknownProtoPacketsReceived int64 `json:"UnknownProtoPacketsReceived"`
	} `json:"Stats,omitempty"`
	LastChange     int  `json:"LastChange,omitempty"`
	LastStatsReset int  `json:"LastStatsReset,omitempty"`
	UID            int  `json:"uid,omitempty"`
	Enable         bool `json:"Enable,omitempty"`
	ResetStats     bool `json:"ResetStats,omitempty"`
}

// ValueResponse represents the full response from the router from the getValue
// method
type ValueResponse struct {
	Device Device `json:"Device,omitempty"`
}

func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	if strings.HasPrefix(s, "0-") {
		// special-case for year 0
		s = "000" + s
	}

	return time.Parse("2006-01-02T15:04:05-0700", s)
}

func (d *DeviceInfo) UnmarshalJSON(b []byte) error {
	type alias DeviceInfo

	aux := struct {
		*alias
		BackupTimeStamp string  `json:"BackupTimeStamp,omitempty"`
		BuildDate       string  `json:"BuildDate,omitempty"`
		FirstUseDate    string  `json:"FirstUseDate,omitempty"`
		RebootStatus    float64 `json:"RebootStatus,omitempty"`
		ResetStatus     float64 `json:"ResetStatus,omitempty"`
		UpdateStatus    float64 `json:"UpdateStatus,omitempty"`
	}{
		alias: (*alias)(d),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	if aux.BackupTimeStamp != "" {
		t, err := parseTimestamp(aux.BackupTimeStamp)
		if err != nil {
			return fmt.Errorf("parseTimestamp: %w", err)
		}

		d.BackupTimeStamp = t
	}

	if aux.BuildDate != "" {
		t, err := parseTimestamp(aux.BuildDate)
		if err != nil {
			return fmt.Errorf("parseTimestamp: %w", err)
		}

		d.BuildDate = t
	}

	d.RebootStatus = int(aux.RebootStatus)
	d.ResetStatus = int(aux.ResetStatus)
	d.UpdateStatus = int(aux.UpdateStatus)

	if aux.FirstUseDate != "" {
		t, err := parseTimestamp(aux.FirstUseDate)
		if err != nil {
			return fmt.Errorf("parseTimestamp: %w", err)
		}

		d.FirstUseDate = t
	}

	d.ModelName = modelName(aux.ModelName)

	return nil
}

func modelName(in string) string {
	switch in {
	case "2864":
		return "Connection Hub"
	case "4350":
		return "Home Hub 1000"
	case "5250":
		return "Home Hub 2000"
	case "5566":
		return "Home Hub 3000"
	case "5689":
		return "Home Hub 4000"
	case "5690":
		return "Giga Hub"
	default:
		slog.Warn("unknown model name", "model_name", in)

		return in
	}
}

type CrashHistory struct {
	LastCrashDate        time.Time `json:"LastCrashDate,omitempty"`
	MonthlyNumberOfCrash int       `json:"MonthlyNumberOfCrash,omitempty"`
	NumberOfCrash        int       `json:"NumberOfCrash,omitempty"`
}

func (c *CrashHistory) UnmarshalJSON(b []byte) error {
	type alias CrashHistory

	aux := struct {
		*alias
		LastCrashDate string `json:"LastCrashDate,omitempty"`
	}{
		alias: (*alias)(c),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	if aux.LastCrashDate != "" {
		t, err := parseTimestamp(aux.LastCrashDate)
		if err != nil {
			return fmt.Errorf("time.Parse: %w", err)
		}

		c.LastCrashDate = t
	}

	return nil
}

type Host struct {
	InterfaceType         string `json:"InterfaceType,omitempty"`
	UserDeviceType        string `json:"UserDeviceType,omitempty"`
	ActiveLastChange      string `json:"ActiveLastChange,omitempty"`
	AddressSource         string `json:"AddressSource,omitempty"`
	Alias                 string `json:"Alias,omitempty"`
	AssociatedDevice      string `json:"AssociatedDevice,omitempty"`
	VendorClassID         string `json:"VendorClassID,omitempty"`
	ClientID              string `json:"ClientID,omitempty"`
	DHCPClient            string `json:"DHCPClient,omitempty"`
	DetectedDeviceType    string `json:"DetectedDeviceType,omitempty"`
	SysfsID               string `json:"SysfsId,omitempty"`
	VendorClassIDv6       string `json:"VendorClassIDv6,omitempty"`
	IPAddress             string `json:"IPAddress,omitempty"`
	HostName              string `json:"HostName,omitempty"`
	DeviceTypeAssociation string `json:"DeviceTypeAssociation,omitempty"`
	UserFriendlyName      string `json:"UserFriendlyName,omitempty"`
	AccessPoint           string `json:"AccessPoint,omitempty"`
	Icon                  string `json:"Icon,omitempty"`
	PhysAddress           string `json:"PhysAddress,omitempty"`
	Layer1Interface       string `json:"Layer1Interface,omitempty"`
	Layer3Interface       string `json:"Layer3Interface,omitempty"`
	UserHostName          string `json:"UserHostName,omitempty"`
	UserClassID           string `json:"UserClassID,omitempty"`
	History               struct {
		AddressSource   string `json:"AddressSource,omitempty"`
		ClientID        string `json:"ClientID,omitempty"`
		HostName        string `json:"HostName,omitempty"`
		IPAddress       string `json:"IPAddress,omitempty"`
		IPv6Address     string `json:"IPv6Address,omitempty"`
		Layer1Interface string `json:"Layer1Interface,omitempty"`
		Layer3Interface string `json:"Layer3Interface,omitempty"`
		UserClassID     string `json:"UserClassID,omitempty"`
		VendorClassID   string `json:"VendorClassID,omitempty"`
		VendorClassIDv6 string `json:"VendorClassIDv6,omitempty"`
		Options         []struct {
			OptionValue string `json:"OptionValue,omitempty"`
			OptionTag   int    `json:"OptionTag,omitempty"`
			UID         int    `json:"uid,omitempty"`
		} `json:"Options,omitempty"`
	} `json:"History,omitempty"`
	IPv6Addresses []json.RawMessage `json:"IPv6Addresses,omitempty"`
	Options       []json.RawMessage `json:"Options,omitempty"`
	IPv4Addresses []struct {
		IPAddress string `json:"IPAddress,omitempty"`
		UID       int    `json:"uid,omitempty"`
		Active    bool   `json:"Active,omitempty"`
	} `json:"IPv4Addresses,omitempty"`
	LeaseTimeRemaining int  `json:"LeaseTimeRemaining,omitempty"`
	UnblockHoursCount  int  `json:"UnblockHoursCount,omitempty"`
	LeaseStart         int  `json:"LeaseStart,omitempty"`
	LeaseDuration      int  `json:"LeaseDuration,omitempty"`
	UID                int  `json:"uid,omitempty"`
	Hidden             bool `json:"Hidden,omitempty"`
	BlacklistStatus    bool `json:"BlacklistStatus,omitempty"`
	Active             bool `json:"Active,omitempty"`
}

type OpticalInterface struct {
	Name              string `json:"Name,omitempty"`
	Alias             string `json:"Alias,omitempty"`
	Alarm             string `json:"Alarm,omitempty"`
	StoppedBy         string `json:"StoppedBy,omitempty"`
	Status            string `json:"Status,omitempty"`
	IfcName           string `json:"IfcName,omitempty"`
	OpticalVendorName string `json:"OpticalVendorName,omitempty"`
	OpticalPartNumber string `json:"OpticalPartNumber,omitempty"`
	LowerLayers       string `json:"LowerLayers,omitempty"`
	SupportedSFPs     []struct {
		PartNumber string `json:"PartNumber,omitempty"`
		Type       string `json:"Type,omitempty"`
		VendorName string `json:"VendorName,omitempty"`
		UID        int    `json:"uid,omitempty"`
	} `json:"SupportedSFPs,omitempty"`
	PonStats struct {
		GemPorts []struct {
			BytesReceived            string `json:"BytesReceived,omitempty"`
			BytesSent                string `json:"BytesSent,omitempty"`
			Direction                string `json:"Direction,omitempty"`
			FlowType                 string `json:"FlowType,omitempty"`
			DiscardedPacketsReceived int    `json:"DiscardedPacketsReceived,omitempty"`
			DiscardedPacketsSent     int    `json:"DiscardedPacketsSent,omitempty"`
			ID                       int    `json:"Id,omitempty"`
			Index                    int    `json:"Index,omitempty"`
			PacketsReceived          int    `json:"PacketsReceived,omitempty"`
			PacketsSent              int    `json:"PacketsSent,omitempty"`
			TcontIndex               int    `json:"TcontIndex,omitempty"`
			UID                      int    `json:"uid,omitempty"`
		} `json:"GemPorts,omitempty"`
		Tconts []struct {
			AllocID        int `json:"AllocId,omitempty"`
			GemPacketsSent int `json:"GemPacketsSent,omitempty"`
			Index          int `json:"Index,omitempty"`
			UID            int `json:"uid,omitempty"`
		} `json:"Tconts,omitempty"`
		Reset bool `json:"Reset,omitempty"`
	} `json:"PonStats,omitempty"`
	CATV struct {
		Alarm            string `json:"Alarm,omitempty"`
		Status           string `json:"Status,omitempty"`
		RfRxOpticalPower int    `json:"RfRxOpticalPower,omitempty"`
		RfVoltage        int    `json:"RfVoltage,omitempty"`
	} `json:"CATV,omitempty"`
	RogueOnu struct {
		RogueOnuStatus          string `json:"RogueOnuStatus,omitempty"`
		RogueOnuOccurrences     []any  `json:"RogueOnuOccurrences,omitempty"`
		RogueOnuCount           int    `json:"RogueOnuCount,omitempty"`
		RogueOnuDetectionEnable bool   `json:"RogueOnuDetectionEnable,omitempty"`
	} `json:"RogueOnu,omitempty"`
	Stats struct {
		BroadcastPacketsReceived      int64 `json:"BroadcastPacketsReceived,omitempty"`
		BroadcastPacketsSent          int64 `json:"BroadcastPacketsSent,omitempty"`
		BytesReceived                 int64 `json:"BytesReceived,omitempty,string"`
		BytesSent                     int64 `json:"BytesSent,omitempty,string"`
		DiscardChecksumReceived       int64 `json:"DiscardChecksumReceived,omitempty"`
		DiscardSequenceNumberReceived int64 `json:"DiscardSequenceNumberReceived,omitempty"`
		ErrorsReceived                int64 `json:"ErrorsReceived,omitempty"`
		ErrorsSent                    int64 `json:"ErrorsSent,omitempty"`
		MulticastPacketsReceived      int64 `json:"MulticastPacketsReceived,omitempty"`
		MulticastPacketsSent          int64 `json:"MulticastPacketsSent,omitempty"`
		PacketsReceived               int64 `json:"PacketsReceived,omitempty"`
		PacketsSent                   int64 `json:"PacketsSent,omitempty"`
		UnicastPacketsReceived        int64 `json:"UnicastPacketsReceived,omitempty"`
		UnicastPacketsSent            int64 `json:"UnicastPacketsSent,omitempty"`
	} `json:"Stats,omitempty"`
	LastChange                  int64 `json:"LastChange,omitempty"`
	BIASCurrent                 int64 `json:"BIASCurrent,omitempty"`
	UID                         int   `json:"uid,omitempty"`
	OpticalSignalLevel          int64 `json:"OpticalSignalLevel,omitempty"`
	LastStatsReset              int   `json:"LastStatsReset,omitempty"`
	Voltage                     int64 `json:"Voltage,omitempty"`
	LowerOpticalThreshold       int64 `json:"LowerOpticalThreshold,omitempty"`
	LowerTransmitPowerThreshold int64 `json:"LowerTransmitPowerThreshold,omitempty"`
	Temperature                 int64 `json:"Temperature,omitempty"`
	TransmitOpticalLevel        int64 `json:"TransmitOpticalLevel,omitempty"`
	UpperOpticalThreshold       int64 `json:"UpperOpticalThreshold,omitempty"`
	UpperTransmitPowerThreshold int64 `json:"UpperTransmitPowerThreshold,omitempty"`
	Upstream                    bool  `json:"Upstream,omitempty"`
	Enable                      bool  `json:"Enable,omitempty"`
	ResetStats                  bool  `json:"ResetStats,omitempty"`
}
type ResourceUsage struct {
	ProcessStatus        ProcessStatuses `json:"ProcessStatus,omitempty"`
	TotalMemory          int64           `json:"TotalMemory,omitempty"`
	FreeMemory           int64           `json:"FreeMemory,omitempty"`
	AvailableFlashMemory int64           `json:"AvailableFlashMemory,omitempty"`
	UsedFlashMemory      int64           `json:"UsedFlashMemory,omitempty"`
	CPUUsage             int64           `json:"CPUUsage,omitempty"`
	LoadAverage          float64         `json:"LoadAverage,omitempty"`
	LoadAverage5         float64         `json:"LoadAverage5,omitempty"`
	LoadAverage15        float64         `json:"LoadAverage15,omitempty"`
}

type ProcessStatuses []ProcessStatus

func (p *ProcessStatuses) UnmarshalJSON(data []byte) error {
	// ProcessStatus is presented as a string with encoded JSON inside - we want
	// to decode it into a slice of structs
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	ps := []ProcessStatus{}

	err := json.Unmarshal([]byte(s), &ps)
	if err != nil {
		return err
	}

	*p = ps

	return nil
}

type ProcessStatus struct {
	ProcessName string `json:"ProcessName"`
	State       string `json:"State"`
	Size        int64  `json:"Size,string"`
	CPUTime     int64  `json:"CPUTime,string"`
	PID         int    `json:"PID,string"`
	Priority    int    `json:"Priority,string"`
}
