package sagemcom_fast_exporter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type requestBody struct {
	Id        int      `json:"id"`
	SessionId int      `json:"session-id"`
	Priority  bool     `json:"priority"`
	Actions   []action `json:"actions"`
	Cnonce    int      `json:"cnonce"`
	AuthKey   string   `json:"auth-key"`
}

type action struct {
	Id         int            `json:"id,omitempty"`
	Method     string         `json:"method"`
	XPath      string         `json:"xpath,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type sessionOptions struct {
	Nss                      []nss           `json:"nss"`
	Language                 string          `json:"language"`
	ContextFlags             contextFlags    `json:"context-flags"`
	CapabilityDepth          int             `json:"capability-depth"`
	CapabilityFlags          capabilityFlags `json:"capability-flags"`
	TimeFormat               string          `json:"time-format"`
	WriteOnlyString          string          `json:"write-only-string"`
	UndefinedWriteOnlyString string          `json:"undefined-write-only-string"`
}

type nss struct {
	Name string `json:"name"`
	Uri  string `json:"uri"`
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
	Uid     int           `json:"uid"`
	Id      int           `json:"id"`
	Error   *xmoError     `json:"error"`
	Actions []actionResp  `json:"actions"`
	Events  []interface{} `json:"events"`
}

type result struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type actionResp struct {
	Uid       int            `json:"uid"`
	Id        int            `json:"id"`
	Error     *xmoError      `json:"error"`
	Callbacks []callbackResp `json:"callbacks"`
}

type callbackResp struct {
	Uid        int                        `json:"uid"`
	Result     *result                    `json:"result"`
	XPath      string                     `json:"xpath"`
	Parameters map[string]json.RawMessage `json:"parameters"`
}

// error types
type xmoError struct {
	Code        int
	Description string
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

type Device struct {
	ARP struct {
	} `json:"ARP,omitempty"`
	DHCPv4 struct {
		Server struct {
			Enable bool `json:"Enable,omitempty"`
			Pools  []struct {
				Alias             string `json:"Alias,omitempty"`
				AllowKnownClients bool   `json:"AllowKnownClients,omitempty"`
				BlockAckFlag      bool   `json:"BlockAckFlag,omitempty"`
				BootFileName      string `json:"BootFileName,omitempty"`
				Chaddr            string `json:"Chaddr,omitempty"`
				ChaddrExclude     bool   `json:"ChaddrExclude,omitempty"`
				ChaddrMask        string `json:"ChaddrMask,omitempty"`
				ClientID          string `json:"ClientID,omitempty"`
				ClientIDExclude   bool   `json:"ClientIDExclude,omitempty"`
				Clients           []struct {
					Active        bool   `json:"Active,omitempty"`
					Alias         string `json:"Alias,omitempty"`
					Chaddr        string `json:"Chaddr,omitempty"`
					IPv4Addresses []struct {
						IPAddress          string `json:"IPAddress,omitempty"`
						LeaseTimeRemaining string `json:"LeaseTimeRemaining,omitempty"`
						UID                int    `json:"uid,omitempty"`
					} `json:"IPv4Addresses,omitempty"`
					Options []struct {
						Tag   int    `json:"Tag,omitempty"`
						Value string `json:"Value,omitempty"`
						UID   int    `json:"uid,omitempty"`
					} `json:"Options,omitempty"`
					UID int `json:"uid,omitempty"`
				} `json:"Clients,omitempty"`
				DHCPServerConfigurable bool   `json:"DHCPServerConfigurable,omitempty"`
				DNSServers             string `json:"DNSServers,omitempty"`
				DomainName             string `json:"DomainName,omitempty"`
				Enable                 bool   `json:"Enable,omitempty"`
				FlushDHCPLeases        bool   `json:"FlushDHCPLeases,omitempty"`
				IPInterface            string `json:"IPInterface,omitempty"`
				IPRouters              string `json:"IPRouters,omitempty"`
				Interface              string `json:"Interface,omitempty"`
				LeaseTime              int    `json:"LeaseTime,omitempty"`
				MaxAddress             string `json:"MaxAddress,omitempty"`
				MinAddress             string `json:"MinAddress,omitempty"`
				NextServer             string `json:"NextServer,omitempty"`
				Options                []struct {
					Alias  string `json:"Alias,omitempty"`
					Enable bool   `json:"Enable,omitempty"`
					Tag    int    `json:"Tag,omitempty"`
					Value  string `json:"Value,omitempty"`
					UID    int    `json:"uid,omitempty"`
				} `json:"Options,omitempty"`
				Order                 int    `json:"Order,omitempty"`
				ReservedAddresses     string `json:"ReservedAddresses,omitempty"`
				ServerName            string `json:"ServerName,omitempty"`
				StaticAddresses       []any  `json:"StaticAddresses,omitempty"`
				Status                string `json:"Status,omitempty"`
				SubnetMask            string `json:"SubnetMask,omitempty"`
				UserClassID           string `json:"UserClassID,omitempty"`
				UserClassIDExclude    bool   `json:"UserClassIDExclude,omitempty"`
				VendorClassID         string `json:"VendorClassID,omitempty"`
				VendorClassIDExclude  bool   `json:"VendorClassIDExclude,omitempty"`
				VendorClassIDMode     string `json:"VendorClassIDMode,omitempty"`
				XSAGEMCOMForceOptions bool   `json:"X_SAGEMCOM_ForceOptions,omitempty"`
				UID                   int    `json:"uid,omitempty"`
			} `json:"Pools,omitempty"`
			XSAGEMCOMAuthoritative bool `json:"X_SAGEMCOM_Authoritative,omitempty"`
			XmoConfVersion         int  `json:"XmoConfVersion,omitempty"`
		} `json:"Server,omitempty"`
	} `json:"DHCPv4,omitempty"`
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
	DNS struct {
		Client struct {
			Attempts          int    `json:"Attempts,omitempty"`
			Enable            bool   `json:"Enable,omitempty"`
			FallbackTimeout   int    `json:"FallbackTimeout,omitempty"`
			GenerateHostsFile bool   `json:"GenerateHostsFile,omitempty"`
			HostName          string `json:"HostName,omitempty"`
			LocalDomains      string `json:"LocalDomains,omitempty"`
			Servers           []struct {
				Alias      string `json:"Alias,omitempty"`
				DNSServer  string `json:"DNSServer,omitempty"`
				Enable     bool   `json:"Enable,omitempty"`
				Interface  string `json:"Interface,omitempty"`
				StaticDNSs []any  `json:"StaticDNSs,omitempty"`
				Status     string `json:"Status,omitempty"`
				Type       string `json:"Type,omitempty"`
				UID        int    `json:"uid,omitempty"`
			} `json:"Servers,omitempty"`
			Status        string `json:"Status,omitempty"`
			UseGUAAddress bool   `json:"UseGUAAddress,omitempty"`
			UseLLAAddress bool   `json:"UseLLAAddress,omitempty"`
			UseULAAddress bool   `json:"UseULAAddress,omitempty"`
		} `json:"Client,omitempty"`
		Diagnostics struct {
			NSLookupDiagnostics struct {
				DNSServer           string `json:"DNSServer,omitempty"`
				DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
				HostName            string `json:"HostName,omitempty"`
				Interface           string `json:"Interface,omitempty"`
				NumberOfRepetitions int    `json:"NumberOfRepetitions,omitempty"`
				Results             []any  `json:"Results,omitempty"`
				SuccessCount        int    `json:"SuccessCount,omitempty"`
				Timeout             int    `json:"Timeout,omitempty"`
			} `json:"NSLookupDiagnostics,omitempty"`
		} `json:"Diagnostics,omitempty"`
		Relay struct {
			AllowedRebindingDomains string `json:"AllowedRebindingDomains,omitempty"`
			Attempts                int    `json:"Attempts,omitempty"`
			Cache                   struct {
				AvailableMemory        int    `json:"AvailableMemory,omitempty"`
				Content                string `json:"Content,omitempty"`
				FlushCache             bool   `json:"FlushCache,omitempty"`
				QueriesAnsweredLocally int    `json:"QueriesAnsweredLocally,omitempty"`
				QueriesForwarded       int    `json:"QueriesForwarded,omitempty"`
				QueriesPerServers      string `json:"QueriesPerServers,omitempty"`
				Status                 string `json:"Status,omitempty"`
				UsageStatistics        string `json:"UsageStatistics,omitempty"`
			} `json:"Cache,omitempty"`
			CacheSize       int  `json:"CacheSize,omitempty"`
			Debug           bool `json:"Debug,omitempty"`
			Enable          bool `json:"Enable,omitempty"`
			FallbackTimeout int  `json:"FallbackTimeout,omitempty"`
			Forwardings     []struct {
				Alias      string `json:"Alias,omitempty"`
				DNSServer  string `json:"DNSServer,omitempty"`
				Enable     bool   `json:"Enable,omitempty"`
				Interface  string `json:"Interface,omitempty"`
				StaticDNSs []any  `json:"StaticDNSs,omitempty"`
				Status     string `json:"Status,omitempty"`
				Type       string `json:"Type,omitempty"`
				UID        int    `json:"uid,omitempty"`
			} `json:"Forwardings,omitempty"`
			HandleRetransmissions bool `json:"HandleRetransmissions,omitempty"`
			InputInterfaces       []struct {
				AcceptInput bool   `json:"AcceptInput,omitempty"`
				Interface   string `json:"Interface,omitempty"`
				UID         int    `json:"uid,omitempty"`
			} `json:"InputInterfaces,omitempty"`
			MaximumTTLServer                int    `json:"MaximumTTLServer,omitempty"`
			MinimumSourcePort               int    `json:"MinimumSourcePort,omitempty"`
			NegativeTTLServer               int    `json:"NegativeTTLServer,omitempty"`
			NoForwardDomains                string `json:"NoForwardDomains,omitempty"`
			RetransmissionTimeout           int    `json:"RetransmissionTimeout,omitempty"`
			ServerQuarantineTimeout         int    `json:"ServerQuarantineTimeout,omitempty"`
			ServerQuarantineTimeoutEndRange int    `json:"ServerQuarantineTimeoutEndRange,omitempty"`
			Status                          string `json:"Status,omitempty"`
			StopDNSRebind                   bool   `json:"StopDNSRebind,omitempty"`
			TryAllNsAfterNxDomain           bool   `json:"TryAllNsAfterNxDomain,omitempty"`
		} `json:"Relay,omitempty"`
		Sd struct {
			Enable   bool  `json:"Enable,omitempty"`
			Services []any `json:"Services,omitempty"`
		} `json:"SD,omitempty"`
		SupportedRecordTypes string `json:"SupportedRecordTypes,omitempty"`
	} `json:"DNS,omitempty"`
	DeviceDiscovery struct {
		AccessPoints []struct {
			Connected bool   `json:"Connected,omitempty"`
			Name      string `json:"Name,omitempty"`
			UID       int    `json:"uid,omitempty"`
		} `json:"AccessPoints,omitempty"`
		DHCPPools            []any `json:"DHCPPools,omitempty"`
		DeviceIdentification struct {
			DHCPFingerprintDatabase struct {
				Entries    []any `json:"Entries,omitempty"`
				MaxEntries int   `json:"MaxEntries,omitempty"`
			} `json:"DHCPFingerprintDatabase,omitempty"`
			DeviceTypes []any `json:"DeviceTypes,omitempty"`
		} `json:"DeviceIdentification,omitempty"`
		Enable     bool `json:"Enable,omitempty"`
		Interfaces []struct {
			Arp  bool   `json:"Arp,omitempty"`
			Path string `json:"Path,omitempty"`
			UID  int    `json:"uid,omitempty"`
		} `json:"Interfaces,omitempty"`
		MaxHosts  int `json:"MaxHosts,omitempty"`
		USBEntity struct {
			Connected bool   `json:"Connected,omitempty"`
			Name      string `json:"Name,omitempty"`
		} `json:"USBEntity,omitempty"`
	} `json:"DeviceDiscovery,omitempty"`
	DeviceInfo    DeviceInfo `json:"DeviceInfo,omitempty"`
	DeviceSummary string     `json:"DeviceSummary,omitempty"`
	Ethernet      struct {
		Interfaces []EthernetInterface `json:"Interfaces,omitempty"`
		Links      []struct {
			Alias           string `json:"Alias,omitempty"`
			Enable          bool   `json:"Enable,omitempty"`
			IfcName         string `json:"IfcName,omitempty"`
			LastChange      int    `json:"LastChange,omitempty"`
			LastStatsReset  int    `json:"LastStatsReset,omitempty"`
			LowerLayers     string `json:"LowerLayers,omitempty"`
			MACAddress      string `json:"MACAddress,omitempty"`
			Name            string `json:"Name,omitempty"`
			PriorityTagging bool   `json:"PriorityTagging,omitempty"`
			ResetStats      bool   `json:"ResetStats,omitempty"`
			Stats           struct {
				BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
				BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
				BytesReceived               string `json:"BytesReceived,omitempty"`
				BytesSent                   string `json:"BytesSent,omitempty"`
				CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
				DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
				DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
				ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
				ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
				MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
				MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
				PacketsReceived             string `json:"PacketsReceived,omitempty"`
				PacketsSent                 string `json:"PacketsSent,omitempty"`
				RetransCount                int    `json:"RetransCount,omitempty"`
				UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
				UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
				UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
			} `json:"Stats,omitempty"`
			Status    string `json:"Status,omitempty"`
			StoppedBy string `json:"StoppedBy,omitempty"`
			UID       int    `json:"uid,omitempty"`
		} `json:"Links,omitempty"`
		OAM struct {
			OAM1731 struct {
				CCMinterval   int    `json:"CCMinterval,omitempty"`
				EnableOAM1731 bool   `json:"EnableOAM1731,omitempty"`
				InterfaceName string `json:"InterfaceName,omitempty"`
				Ccm           bool   `json:"ccm,omitempty"`
				Loopback      int    `json:"loopback,omitempty"`
				Meg           int    `json:"meg,omitempty"`
				MegLevel      int    `json:"megLevel,omitempty"`
				MepID         int    `json:"mepId,omitempty"`
				Vlan          int    `json:"vlan,omitempty"`
			} `json:"OAM1731,omitempty"`
			OAM1ag struct {
				CCMinterval   int    `json:"CCMinterval,omitempty"`
				EnableOAM1Ag  bool   `json:"EnableOAM1ag,omitempty"`
				InterfaceName string `json:"InterfaceName,omitempty"`
				Ccm           bool   `json:"ccm,omitempty"`
				Loopback      int    `json:"loopback,omitempty"`
				Ma            int    `json:"ma,omitempty"`
				Md            int    `json:"md,omitempty"`
				MdLevel       int    `json:"mdLevel,omitempty"`
				MegLevel      int    `json:"megLevel,omitempty"`
				MepID         int    `json:"mepId,omitempty"`
				Vlan          int    `json:"vlan,omitempty"`
			} `json:"OAM1ag,omitempty"`
			OAM3ah struct {
				EnableOAM3Ah  bool   `json:"EnableOAM3ah,omitempty"`
				InterfaceName string `json:"InterfaceName,omitempty"`
				Features      int    `json:"features,omitempty"`
				Loopback      int    `json:"loopback,omitempty"`
				OamID         int    `json:"oamID,omitempty"`
			} `json:"OAM3ah,omitempty"`
		} `json:"OAM,omitempty"`
		RMONStatistics   []any `json:"RMONStatistics,omitempty"`
		VLANTerminations []struct {
			Alias                   string `json:"Alias,omitempty"`
			EgressPriorityMappings  string `json:"EgressPriorityMappings,omitempty"`
			Enable                  bool   `json:"Enable,omitempty"`
			IfcName                 string `json:"IfcName,omitempty"`
			IngressPriorityMappings string `json:"IngressPriorityMappings,omitempty"`
			LastChange              int    `json:"LastChange,omitempty"`
			LastStatsReset          int    `json:"LastStatsReset,omitempty"`
			LowerLayers             string `json:"LowerLayers,omitempty"`
			Name                    string `json:"Name,omitempty"`
			ResetStats              bool   `json:"ResetStats,omitempty"`
			Stats                   struct {
				BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
				BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
				BytesReceived               string `json:"BytesReceived,omitempty"`
				BytesSent                   string `json:"BytesSent,omitempty"`
				CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
				DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
				DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
				ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
				ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
				MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
				MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
				PacketsReceived             string `json:"PacketsReceived,omitempty"`
				PacketsSent                 string `json:"PacketsSent,omitempty"`
				RetransCount                int    `json:"RetransCount,omitempty"`
				UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
				UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
				UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
			} `json:"Stats,omitempty"`
			Status    string `json:"Status,omitempty"`
			StoppedBy string `json:"StoppedBy,omitempty"`
			Tpid      int    `json:"TPID,omitempty"`
			Untagged  bool   `json:"Untagged,omitempty"`
			Vlanid    int    `json:"VLANID,omitempty"`
			UID       int    `json:"uid,omitempty"`
		} `json:"VLANTerminations,omitempty"`
	} `json:"Ethernet,omitempty"`
	Firewall struct {
		AdvancedLevel            string `json:"AdvancedLevel,omitempty"`
		BlockFragmentedIPPackets bool   `json:"BlockFragmentedIPPackets,omitempty"`
		Chains                   []struct {
			Alias   string `json:"Alias,omitempty"`
			Creator string `json:"Creator,omitempty"`
			Enable  bool   `json:"Enable,omitempty"`
			Name    string `json:"Name,omitempty"`
			Rules   []struct {
				Alias                  string `json:"Alias,omitempty"`
				CreationDate           string `json:"CreationDate,omitempty"`
				Creator                string `json:"Creator,omitempty"`
				Dscp                   int    `json:"DSCP,omitempty"`
				DSCPExclude            bool   `json:"DSCPExclude,omitempty"`
				Description            string `json:"Description,omitempty"`
				DestAllInterfaces      bool   `json:"DestAllInterfaces,omitempty"`
				DestIP                 string `json:"DestIP,omitempty"`
				DestIPExclude          bool   `json:"DestIPExclude,omitempty"`
				DestInterface          string `json:"DestInterface,omitempty"`
				DestInterfaceExclude   bool   `json:"DestInterfaceExclude,omitempty"`
				DestMask               string `json:"DestMask,omitempty"`
				DestPort               int    `json:"DestPort,omitempty"`
				DestPortExclude        bool   `json:"DestPortExclude,omitempty"`
				DestPortRangeMax       int    `json:"DestPortRangeMax,omitempty"`
				Enable                 bool   `json:"Enable,omitempty"`
				ExpiryDate             string `json:"ExpiryDate,omitempty"`
				IPVersion              int    `json:"IPVersion,omitempty"`
				Log                    bool   `json:"Log,omitempty"`
				MacID                  string `json:"MacId,omitempty"`
				Order                  int64  `json:"Order,omitempty"`
				Protocol               string `json:"Protocol,omitempty"`
				ProtocolExclude        bool   `json:"ProtocolExclude,omitempty"`
				ProtocolNumber         int    `json:"ProtocolNumber,omitempty"`
				Service                string `json:"Service,omitempty"`
				SourceAllInterfaces    bool   `json:"SourceAllInterfaces,omitempty"`
				SourceIP               string `json:"SourceIP,omitempty"`
				SourceIPExclude        bool   `json:"SourceIPExclude,omitempty"`
				SourceInterface        string `json:"SourceInterface,omitempty"`
				SourceInterfaceExclude bool   `json:"SourceInterfaceExclude,omitempty"`
				SourceMask             string `json:"SourceMask,omitempty"`
				SourcePort             int    `json:"SourcePort,omitempty"`
				SourcePortExclude      bool   `json:"SourcePortExclude,omitempty"`
				SourcePortRangeMax     int    `json:"SourcePortRangeMax,omitempty"`
				Status                 string `json:"Status,omitempty"`
				Target                 string `json:"Target,omitempty"`
				TargetChain            string `json:"TargetChain,omitempty"`
				UID                    int    `json:"uid,omitempty"`
			} `json:"Rules,omitempty"`
			UID int `json:"uid,omitempty"`
		} `json:"Chains,omitempty"`
		Config     string `json:"Config,omitempty"`
		Enable     bool   `json:"Enable,omitempty"`
		Interfaces []struct {
			EnableIPSourceCheck    bool   `json:"EnableIpSourceCheck,omitempty"`
			IPv4IcmpFloodDetection int    `json:"IPv4IcmpFloodDetection,omitempty"`
			IPv4PortScanDetection  int    `json:"IPv4PortScanDetection,omitempty"`
			IPv4SynFloodDetection  int    `json:"IPv4SynFloodDetection,omitempty"`
			IPv4UDPFloodDetection  int    `json:"IPv4UdpFloodDetection,omitempty"`
			IPv6IcmpFloodDetection int    `json:"IPv6IcmpFloodDetection,omitempty"`
			IPv6PortScanDetection  int    `json:"IPv6PortScanDetection,omitempty"`
			IPv6SynFloodDetection  int    `json:"IPv6SynFloodDetection,omitempty"`
			IPv6UDPFloodDetection  int    `json:"IPv6UdpFloodDetection,omitempty"`
			Interface              string `json:"Interface,omitempty"`
			RespondToPing4         bool   `json:"RespondToPing4,omitempty"`
			RespondToPing6         bool   `json:"RespondToPing6,omitempty"`
			SendPing4              bool   `json:"SendPing4,omitempty"`
			SendPing6              bool   `json:"SendPing6,omitempty"`
			UID                    int    `json:"uid,omitempty"`
		} `json:"Interfaces,omitempty"`
		LanInterface string `json:"LanInterface,omitempty"`
		LastChange   string `json:"LastChange,omitempty"`
		Levels       []struct {
			Alias              string `json:"Alias,omitempty"`
			Chain              string `json:"Chain,omitempty"`
			DefaultLogPolicy   bool   `json:"DefaultLogPolicy,omitempty"`
			DefaultPolicy      string `json:"DefaultPolicy,omitempty"`
			Description        string `json:"Description,omitempty"`
			Name               string `json:"Name,omitempty"`
			Order              int    `json:"Order,omitempty"`
			PortMappingEnabled bool   `json:"PortMappingEnabled,omitempty"`
			UID                int    `json:"uid,omitempty"`
		} `json:"Levels,omitempty"`
		PortScanDetection bool   `json:"PortScanDetection,omitempty"`
		Type              string `json:"Type,omitempty"`
		Version           string `json:"Version,omitempty"`
	} `json:"Firewall,omitempty"`
	GRE struct {
		Filters []any `json:"Filters,omitempty"`
		Tunnels []any `json:"Tunnels,omitempty"`
		Vlans   []any `json:"Vlans,omitempty"`
	} `json:"GRE,omitempty"`
	GatewayInfo struct {
		ManufacturerOUI string `json:"ManufacturerOUI,omitempty"`
		ProductClass    string `json:"ProductClass,omitempty"`
	} `json:"GatewayInfo,omitempty"`
	HomePlug struct {
		Enable            bool   `json:"Enable,omitempty"`
		Interfaces        []any  `json:"Interfaces,omitempty"`
		LastDetectionDate string `json:"LastDetectionDate,omitempty"`
		NetworkInterfaces string `json:"NetworkInterfaces,omitempty"`
		Status            string `json:"Status,omitempty"`
	} `json:"HomePlug,omitempty"`
	Hosts struct {
		Hosts                     []Host `json:"Hosts,omitempty"`
		MaxHosts                  int    `json:"MaxHosts,omitempty"`
		STBVendorClassIDList      string `json:"STBVendorClassIDList,omitempty"`
		SweepARP                  int    `json:"SweepARP,omitempty"`
		VAPVendorClassIDList      string `json:"VAPVendorClassIDList,omitempty"`
		WiFiPODSVendorClassIDList string `json:"WiFiPODSVendorClassIDList,omitempty"`
	} `json:"Hosts,omitempty"`
	IP struct {
		ActivePorts []any `json:"ActivePorts,omitempty"`
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
				Dscp                int    `json:"DSCP,omitempty"`
				DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
				DownloadTransports  string `json:"DownloadTransports,omitempty"`
				DownloadURL         string `json:"DownloadURL,omitempty"`
				EOMTime             string `json:"EOMTime,omitempty"`
				EthernetPriority    int    `json:"EthernetPriority,omitempty"`
				Interface           string `json:"Interface,omitempty"`
				ROMTime             string `json:"ROMTime,omitempty"`
				TCPOpenRequestTime  string `json:"TCPOpenRequestTime,omitempty"`
				TCPOpenResponseTime string `json:"TCPOpenResponseTime,omitempty"`
				TestBytesReceived   int    `json:"TestBytesReceived,omitempty"`
				TotalBytesReceived  int    `json:"TotalBytesReceived,omitempty"`
			} `json:"DownloadDiagnostics,omitempty"`
			IPPing struct {
				AverageResponseTime         int    `json:"AverageResponseTime,omitempty"`
				AverageResponseTimeDetailed int    `json:"AverageResponseTimeDetailed,omitempty"`
				Df                          bool   `json:"DF,omitempty"`
				Dscp                        int    `json:"DSCP,omitempty"`
				DataBlockSize               int    `json:"DataBlockSize,omitempty"`
				DiagnosticsState            string `json:"DiagnosticsState,omitempty"`
				FailureCount                int    `json:"FailureCount,omitempty"`
				Host                        string `json:"Host,omitempty"`
				IPAddressUsed               string `json:"IPAddressUsed,omitempty"`
				Interface                   string `json:"Interface,omitempty"`
				MaximumResponseTime         int    `json:"MaximumResponseTime,omitempty"`
				MaximumResponseTimeDetailed int    `json:"MaximumResponseTimeDetailed,omitempty"`
				MinimumResponseTime         int    `json:"MinimumResponseTime,omitempty"`
				MinimumResponseTimeDetailed int    `json:"MinimumResponseTimeDetailed,omitempty"`
				NumberOfRepetitions         int    `json:"NumberOfRepetitions,omitempty"`
				ProtocolVersion             string `json:"ProtocolVersion,omitempty"`
				SuccessCount                int    `json:"SuccessCount,omitempty"`
				Timeout                     int    `json:"Timeout,omitempty"`
			} `json:"IPPing,omitempty"`
			IPv4PingSupported       bool `json:"IPv4PingSupported,omitempty"`
			IPv4TraceRouteSupported bool `json:"IPv4TraceRouteSupported,omitempty"`
			IPv6PingSupported       bool `json:"IPv6PingSupported,omitempty"`
			IPv6TraceRouteSupported bool `json:"IPv6TraceRouteSupported,omitempty"`
			SpeedTest               struct {
				BlockTraffic      bool   `json:"BlockTraffic,omitempty"`
				DiagnosticsState  string `json:"DiagnosticsState,omitempty"`
				DiagnosticsStatus string `json:"DiagnosticsStatus,omitempty"`
				Download          string `json:"Download,omitempty"`
				History           struct {
					BlockTraffic          string `json:"BlockTraffic,omitempty"`
					Download              string `json:"Download,omitempty"`
					Index                 int    `json:"Index,omitempty"`
					Latency               string `json:"Latency,omitempty"`
					SelectedServerAddress string `json:"SelectedServerAddress,omitempty"`
					Timestamp             string `json:"Timestamp,omitempty"`
					Upload                string `json:"Upload,omitempty"`
				} `json:"History,omitempty"`
				Latency               int    `json:"Latency,omitempty"`
				MaxDownload           string `json:"MaxDownload,omitempty"`
				MaxRate               int    `json:"MaxRate,omitempty"`
				MaxUpload             string `json:"MaxUpload,omitempty"`
				SelectedServerAddress string `json:"SelectedServerAddress,omitempty"`
				ServerList            string `json:"ServerList,omitempty"`
				ServerTestCount       int    `json:"ServerTestCount,omitempty"`
				Upload                string `json:"Upload,omitempty"`
			} `json:"SpeedTest,omitempty"`
			TraceRoute struct {
				Dscp             int    `json:"DSCP,omitempty"`
				DataBlockSize    int    `json:"DataBlockSize,omitempty"`
				DiagnosticsState string `json:"DiagnosticsState,omitempty"`
				Host             string `json:"Host,omitempty"`
				IPAddressUsed    string `json:"IPAddressUsed,omitempty"`
				Interface        string `json:"Interface,omitempty"`
				MaxHopCount      int    `json:"MaxHopCount,omitempty"`
				NumberOfTries    int    `json:"NumberOfTries,omitempty"`
				ProtocolVersion  string `json:"ProtocolVersion,omitempty"`
				ResponseTime     int    `json:"ResponseTime,omitempty"`
				RouteHops        []any  `json:"RouteHops,omitempty"`
				Timeout          int    `json:"Timeout,omitempty"`
			} `json:"TraceRoute,omitempty"`
			UDPEchoConfig struct {
				BytesReceived           int    `json:"BytesReceived,omitempty"`
				BytesResponded          int    `json:"BytesResponded,omitempty"`
				EchoPlusEnabled         bool   `json:"EchoPlusEnabled,omitempty"`
				EchoPlusSupported       bool   `json:"EchoPlusSupported,omitempty"`
				Enable                  bool   `json:"Enable,omitempty"`
				Interface               string `json:"Interface,omitempty"`
				PacketsReceived         int    `json:"PacketsReceived,omitempty"`
				PacketsResponded        int    `json:"PacketsResponded,omitempty"`
				SourceIPAddress         string `json:"SourceIPAddress,omitempty"`
				TimeFirstPacketReceived string `json:"TimeFirstPacketReceived,omitempty"`
				TimeLastPacketReceived  string `json:"TimeLastPacketReceived,omitempty"`
				UDPPort                 int    `json:"UDPPort,omitempty"`
			} `json:"UDPEchoConfig,omitempty"`
			UploadDiagnostics struct {
				BOMTime             string `json:"BOMTime,omitempty"`
				Dscp                int    `json:"DSCP,omitempty"`
				DiagnosticsState    string `json:"DiagnosticsState,omitempty"`
				EOMTime             string `json:"EOMTime,omitempty"`
				EthernetPriority    int    `json:"EthernetPriority,omitempty"`
				Interface           string `json:"Interface,omitempty"`
				ROMTime             string `json:"ROMTime,omitempty"`
				TCPOpenRequestTime  string `json:"TCPOpenRequestTime,omitempty"`
				TCPOpenResponseTime string `json:"TCPOpenResponseTime,omitempty"`
				TestFileLength      int    `json:"TestFileLength,omitempty"`
				TotalBytesSent      int    `json:"TotalBytesSent,omitempty"`
				UploadTransports    string `json:"UploadTransports,omitempty"`
				UploadURL           string `json:"UploadURL,omitempty"`
			} `json:"UploadDiagnostics,omitempty"`
		} `json:"Diagnostics,omitempty"`
		IPv4Capable bool   `json:"IPv4Capable,omitempty"`
		IPv4Enable  bool   `json:"IPv4Enable,omitempty"`
		IPv4Status  string `json:"IPv4Status,omitempty"`
		IPv6Capable bool   `json:"IPv6Capable,omitempty"`
		IPv6Enable  bool   `json:"IPv6Enable,omitempty"`
		IPv6Status  string `json:"IPv6Status,omitempty"`
		Interfaces  []struct {
			Alias          string `json:"Alias,omitempty"`
			AliasID        int    `json:"Alias_id,omitempty"`
			AutoIPEnable   bool   `json:"AutoIPEnable,omitempty"`
			CurrentMTUSize int    `json:"CurrentMTUSize,omitempty"`
			DHCPRelease    bool   `json:"DHCPRelease,omitempty"`
			Enable         bool   `json:"Enable,omitempty"`
			IPv4Addresses  []struct {
				AddressingType string `json:"AddressingType,omitempty"`
				Alias          string `json:"Alias,omitempty"`
				DNS            string `json:"Dns,omitempty"`
				Enable         bool   `json:"Enable,omitempty"`
				IPAddress      string `json:"IPAddress,omitempty"`
				IPGateway      string `json:"IPGateway,omitempty"`
				Status         string `json:"Status,omitempty"`
				SubnetMask     string `json:"SubnetMask,omitempty"`
				UID            int    `json:"uid,omitempty"`
			} `json:"IPv4Addresses,omitempty"`
			IPv4Enable    bool `json:"IPv4Enable,omitempty"`
			IPv6Addresses []struct {
				Alias             string `json:"Alias,omitempty"`
				Anycast           bool   `json:"Anycast,omitempty"`
				Enable            bool   `json:"Enable,omitempty"`
				IPAddress         string `json:"IPAddress,omitempty"`
				IPAddressStatus   string `json:"IPAddressStatus,omitempty"`
				Origin            string `json:"Origin,omitempty"`
				PreferredLifetime string `json:"PreferredLifetime,omitempty"`
				Prefix            string `json:"Prefix,omitempty"`
				Status            string `json:"Status,omitempty"`
				ValidLifetime     string `json:"ValidLifetime,omitempty"`
				UID               int    `json:"uid,omitempty"`
			} `json:"IPv6Addresses,omitempty"`
			IPv6Enable   bool `json:"IPv6Enable,omitempty"`
			IPv6Prefixes []struct {
				Alias             string `json:"Alias,omitempty"`
				Autonomous        bool   `json:"Autonomous,omitempty"`
				ChildPrefixBits   string `json:"ChildPrefixBits,omitempty"`
				Enable            bool   `json:"Enable,omitempty"`
				OnLink            bool   `json:"OnLink,omitempty"`
				Origin            string `json:"Origin,omitempty"`
				ParentPrefix      string `json:"ParentPrefix,omitempty"`
				PreferredLifetime string `json:"PreferredLifetime,omitempty"`
				Prefix            string `json:"Prefix,omitempty"`
				PrefixStatus      string `json:"PrefixStatus,omitempty"`
				StaticType        string `json:"StaticType,omitempty"`
				Status            string `json:"Status,omitempty"`
				ValidLifetime     string `json:"ValidLifetime,omitempty"`
				UID               int    `json:"uid,omitempty"`
			} `json:"IPv6Prefixes,omitempty"`
			IfcName        string `json:"IfcName,omitempty"`
			LastChange     int    `json:"LastChange,omitempty"`
			LastStatsReset int    `json:"LastStatsReset,omitempty"`
			Loopback       bool   `json:"Loopback,omitempty"`
			LowerLayers    string `json:"LowerLayers,omitempty"`
			MaxMTUSize     int    `json:"MaxMTUSize,omitempty"`
			Name           string `json:"Name,omitempty"`
			Reset          bool   `json:"Reset,omitempty"`
			ResetStats     bool   `json:"ResetStats,omitempty"`
			Router         string `json:"Router,omitempty"`
			Stats          struct {
				BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
				BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
				BytesReceived               string `json:"BytesReceived,omitempty"`
				BytesSent                   string `json:"BytesSent,omitempty"`
				CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
				DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
				DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
				ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
				ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
				MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
				MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
				PacketsReceived             string `json:"PacketsReceived,omitempty"`
				PacketsSent                 string `json:"PacketsSent,omitempty"`
				RetransCount                int    `json:"RetransCount,omitempty"`
				UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
				UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
				UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
			} `json:"Stats,omitempty"`
			Status    string `json:"Status,omitempty"`
			StoppedBy string `json:"StoppedBy,omitempty"`
			Type      string `json:"Type,omitempty"`
			ULAEnable bool   `json:"ULAEnable,omitempty"`
			UID       int    `json:"uid,omitempty"`
		} `json:"Interfaces,omitempty"`
		TCPConnections int    `json:"TCPConnections,omitempty"`
		ULAPrefix      string `json:"ULAPrefix,omitempty"`
		XmoConfVersion int    `json:"XmoConfVersion,omitempty"`
	} `json:"IP,omitempty"`
	ISMv2 struct {
		DeviceInets []struct {
			Alias      string `json:"Alias,omitempty"`
			Dscp       int    `json:"DSCP,omitempty"`
			Enable     bool   `json:"Enable,omitempty"`
			Interface  string `json:"Interface,omitempty"`
			Name       string `json:"Name,omitempty"`
			PortListen int    `json:"PortListen,omitempty"`
			PortNotice int    `json:"PortNotice,omitempty"`
			Start      bool   `json:"Start,omitempty"`
			TLS        struct {
				Enable    bool   `json:"Enable,omitempty"`
				PKIClient string `json:"PKIClient,omitempty"`
				PKIServer string `json:"PKIServer,omitempty"`
			} `json:"TLS,omitempty"`
			TimerNoticeCheckRecv int `json:"TimerNoticeCheckRecv,omitempty"`
			TimerNoticeSend      int `json:"TimerNoticeSend,omitempty"`
			UID                  int `json:"uid,omitempty"`
		} `json:"DeviceInets,omitempty"`
		PKIClients []any `json:"PKIClients,omitempty"`
		PKIServers []any `json:"PKIServers,omitempty"`
	} `json:"ISMv2,omitempty"`
	LANConfigSecurity struct {
		ConfigPassword string `json:"ConfigPassword,omitempty"`
	} `json:"LANConfigSecurity,omitempty"`
	MQTT struct {
		Capabilities struct {
			MaxNumberOfBrokerBridgeSubscriptions int    `json:"MaxNumberOfBrokerBridgeSubscriptions,omitempty"`
			MaxNumberOfBrokerBridges             int    `json:"MaxNumberOfBrokerBridges,omitempty"`
			MaxNumberOfClientSubscriptions       int    `json:"MaxNumberOfClientSubscriptions,omitempty"`
			ProtocolVersionsSupported            string `json:"ProtocolVersionsSupported,omitempty"`
			TransportProtocolSupported           string `json:"TransportProtocolSupported,omitempty"`
		} `json:"Capabilities,omitempty"`
		Clients []struct {
			Alias            string `json:"Alias,omitempty"`
			BrokerAddress    string `json:"BrokerAddress,omitempty"`
			BrokerPort       int    `json:"BrokerPort,omitempty"`
			CaFile           string `json:"CaFile,omitempty"`
			CaPath           string `json:"CaPath,omitempty"`
			CertFile         string `json:"CertFile,omitempty"`
			CleanSession     bool   `json:"CleanSession,omitempty"`
			ClientID         string `json:"ClientID,omitempty"`
			ConnectRetryTime int    `json:"ConnectRetryTime,omitempty"`
			Enable           bool   `json:"Enable,omitempty"`
			ForceReconnect   bool   `json:"ForceReconnect,omitempty"`
			Interface        string `json:"Interface,omitempty"`
			KeepAliveTime    int    `json:"KeepAliveTime,omitempty"`
			KeyFile          string `json:"KeyFile,omitempty"`
			MessageRetryTime int    `json:"MessageRetryTime,omitempty"`
			Name             string `json:"Name,omitempty"`
			Password         string `json:"Password,omitempty"`
			ProtocolVersion  string `json:"ProtocolVersion,omitempty"`
			Stats            struct {
				BrokerConnectionEstablished string `json:"BrokerConnectionEstablished,omitempty"`
				ConnectionErrors            int    `json:"ConnectionErrors,omitempty"`
				LastPublishMessageReceived  string `json:"LastPublishMessageReceived,omitempty"`
				LastPublishMessageSent      string `json:"LastPublishMessageSent,omitempty"`
				MQTTMessagesReceived        string `json:"MQTTMessagesReceived,omitempty"`
				MQTTMessagesSent            string `json:"MQTTMessagesSent,omitempty"`
				PublishErrors               int    `json:"PublishErrors,omitempty"`
				PublishReceived             string `json:"PublishReceived,omitempty"`
				PublishSent                 string `json:"PublishSent,omitempty"`
				SubscribeSent               string `json:"SubscribeSent,omitempty"`
				UnSubscribeSent             string `json:"UnSubscribeSent,omitempty"`
			} `json:"Stats,omitempty"`
			Status                 string `json:"Status,omitempty"`
			SubscriptionFileConfig string `json:"SubscriptionFileConfig,omitempty"`
			Subscriptions          []any  `json:"Subscriptions,omitempty"`
			TLSInsecure            bool   `json:"TlsInsecure,omitempty"`
			TransportProtocol      string `json:"TransportProtocol,omitempty"`
			Username               string `json:"Username,omitempty"`
			WillEnable             bool   `json:"WillEnable,omitempty"`
			WillQoS                int    `json:"WillQoS,omitempty"`
			WillRetain             bool   `json:"WillRetain,omitempty"`
			WillTopic              string `json:"WillTopic,omitempty"`
			WillValue              string `json:"WillValue,omitempty"`
			UID                    int    `json:"uid,omitempty"`
		} `json:"Clients,omitempty"`
		Enable bool `json:"Enable,omitempty"`
	} `json:"MQTT,omitempty"`
	NAT struct {
		IPSecPassthroughEnable bool `json:"IPSecPassthroughEnable,omitempty"`
		InterfaceSettings      []struct {
			Alias     string `json:"Alias,omitempty"`
			Enable    bool   `json:"Enable,omitempty"`
			Interface string `json:"Interface,omitempty"`
			SourceIP  string `json:"SourceIP,omitempty"`
			Status    string `json:"Status,omitempty"`
			UID       int    `json:"uid,omitempty"`
		} `json:"InterfaceSettings,omitempty"`
		PPTPPassthroughEnable bool `json:"PPTPPassthroughEnable,omitempty"`
		PortMappings          []struct {
			Alias                 string `json:"Alias,omitempty"`
			AllExternalInterfaces bool   `json:"AllExternalInterfaces,omitempty"`
			Creator               string `json:"Creator,omitempty"`
			Description           string `json:"Description,omitempty"`
			Enable                bool   `json:"Enable,omitempty"`
			ExternalInterface     string `json:"ExternalInterface,omitempty"`
			ExternalPort          int    `json:"ExternalPort,omitempty"`
			ExternalPortEndRange  int    `json:"ExternalPortEndRange,omitempty"`
			InternalClient        string `json:"InternalClient,omitempty"`
			InternalInterface     string `json:"InternalInterface,omitempty"`
			InternalPort          int    `json:"InternalPort,omitempty"`
			LeaseDuration         int    `json:"LeaseDuration,omitempty"`
			LeaseStart            string `json:"LeaseStart,omitempty"`
			Protocol              string `json:"Protocol,omitempty"`
			PublicIP              string `json:"PublicIP,omitempty"`
			RemoteHost            string `json:"RemoteHost,omitempty"`
			Service               string `json:"Service,omitempty"`
			Status                string `json:"Status,omitempty"`
			Target                string `json:"Target,omitempty"`
			UID                   int    `json:"uid,omitempty"`
		} `json:"PortMappings,omitempty"`
		SipAlgSubnet          string `json:"SipAlgSubnet,omitempty"`
		XSAGEMCOMSIPALGEnable bool   `json:"X_SAGEMCOM_SIPALGEnable,omitempty"`
	} `json:"NAT,omitempty"`
	NeighborDiscovery struct {
		Enable            bool `json:"Enable,omitempty"`
		InterfaceSettings []struct {
			Alias                   string `json:"Alias,omitempty"`
			Enable                  bool   `json:"Enable,omitempty"`
			Interface               string `json:"Interface,omitempty"`
			MaxRtrSolicitations     int    `json:"MaxRtrSolicitations,omitempty"`
			NUDEnable               bool   `json:"NUDEnable,omitempty"`
			RSEnable                bool   `json:"RSEnable,omitempty"`
			RetransTimer            int    `json:"RetransTimer,omitempty"`
			RtrSolicitationInterval int    `json:"RtrSolicitationInterval,omitempty"`
			Status                  string `json:"Status,omitempty"`
			UID                     int    `json:"uid,omitempty"`
		} `json:"InterfaceSettings,omitempty"`
	} `json:"NeighborDiscovery,omitempty"`
	Optical struct {
		G988 struct {
			Debug               bool `json:"Debug,omitempty"`
			EquipmentManagement struct {
				Onu2G struct {
					EquipmentID       string `json:"EquipmentId,omitempty"`
					VendorProductCode int    `json:"VendorProductCode,omitempty"`
				} `json:"Onu2G,omitempty"`
				OnuG struct {
					SerialNumber            string `json:"SerialNumber,omitempty"`
					TrafficManagementOption int    `json:"TrafficManagementOption,omitempty"`
					VendorID                string `json:"VendorId,omitempty"`
					Version                 string `json:"Version,omitempty"`
				} `json:"OnuG,omitempty"`
				SoftwareImages []struct {
					IsActive        bool   `json:"IsActive,omitempty"`
					IsCommitted     bool   `json:"IsCommitted,omitempty"`
					IsValid         bool   `json:"IsValid,omitempty"`
					ManagedEntityID int    `json:"ManagedEntityId,omitempty"`
					Version         string `json:"Version,omitempty"`
					UID             int    `json:"uid,omitempty"`
				} `json:"SoftwareImages,omitempty"`
			} `json:"EquipmentManagement,omitempty"`
			General struct {
				OltG struct {
					EquipmentID string `json:"EquipmentId,omitempty"`
					OltVendorID string `json:"OltVendorId,omitempty"`
					Version     string `json:"Version,omitempty"`
				} `json:"OltG,omitempty"`
			} `json:"General,omitempty"`
			GponState string `json:"GponState,omitempty"`
			Logging   struct {
				Destination string `json:"Destination,omitempty"`
				Level       string `json:"Level,omitempty"`
			} `json:"Logging,omitempty"`
			OnuMode         string `json:"OnuMode,omitempty"`
			OperatorConf    bool   `json:"OperatorConf,omitempty"`
			QosModeRG       bool   `json:"QosModeRG,omitempty"`
			RegID           string `json:"RegId,omitempty"`
			Software0UbiDev string `json:"Software0UbiDev,omitempty"`
			Software1UbiDev string `json:"Software1UbiDev,omitempty"`
		} `json:"G988,omitempty"`
		Interfaces []OpticalInterface `json:"Interfaces,omitempty"`
	} `json:"Optical,omitempty"`
	PPP struct {
		Interfaces []struct {
			Alias                               string `json:"Alias,omitempty"`
			AuthenticationProtocol              string `json:"AuthenticationProtocol,omitempty"`
			AutoDisconnectTime                  int    `json:"AutoDisconnectTime,omitempty"`
			BFState                             string `json:"BFState,omitempty"`
			ChapMaxResponse                     int    `json:"ChapMaxResponse,omitempty"`
			ChapResponseRestart                 int    `json:"ChapResponseRestart,omitempty"`
			CompressionProtocol                 string `json:"CompressionProtocol,omitempty"`
			ConnectionStatus                    string `json:"ConnectionStatus,omitempty"`
			ConnectionTrigger                   string `json:"ConnectionTrigger,omitempty"`
			CurrentMRUSize                      int    `json:"CurrentMRUSize,omitempty"`
			DefaultRoute                        string `json:"DefaultRoute,omitempty"`
			Enable                              bool   `json:"Enable,omitempty"`
			EncryptionProtocol                  string `json:"EncryptionProtocol,omitempty"`
			Holdoff                             int    `json:"Holdoff,omitempty"`
			HoldoffAuthFailedAdd                int    `json:"HoldoffAuthFailedAdd,omitempty"`
			HoldoffAuthFailedAdditionalsRetries int    `json:"HoldoffAuthFailedAdditionalsRetries,omitempty"`
			HoldoffAuthFailedInit               int    `json:"HoldoffAuthFailedInit,omitempty"`
			HoldoffAuthFailedMax                int    `json:"HoldoffAuthFailedMax,omitempty"`
			HoldoffAuthFailedRetries            int    `json:"HoldoffAuthFailedRetries,omitempty"`
			HoldoffLcpEchoTimeout               bool   `json:"HoldoffLcpEchoTimeout,omitempty"`
			HoldoffPeerNoResource               bool   `json:"HoldoffPeerNoResource,omitempty"`
			IPCP                                struct {
				DNSServers          string `json:"DNSServers,omitempty"`
				LocalIPAddress      string `json:"LocalIPAddress,omitempty"`
				PassthroughDHCPPool string `json:"PassthroughDHCPPool,omitempty"`
				PassthroughEnable   bool   `json:"PassthroughEnable,omitempty"`
				RemoteIPAddress     string `json:"RemoteIPAddress,omitempty"`
			} `json:"IPCP,omitempty"`
			IPCPEnable bool `json:"IPCPEnable,omitempty"`
			IPv6CP     struct {
				Eui64UseEnable            bool   `json:"Eui64UseEnable,omitempty"`
				LocalInterfaceIdentifier  string `json:"LocalInterfaceIdentifier,omitempty"`
				RemoteInterfaceIdentifier string `json:"RemoteInterfaceIdentifier,omitempty"`
			} `json:"IPv6CP,omitempty"`
			IPv6CPEnable                bool     `json:"IPv6CPEnable,omitempty"`
			IdleDisconnectTime          int      `json:"IdleDisconnectTime,omitempty"`
			IfcName                     string   `json:"IfcName,omitempty"`
			InternalLastConnectionError string   `json:"InternalLastConnectionError,omitempty"`
			IpcpMaxConfigure            int      `json:"IpcpMaxConfigure,omitempty"`
			IpcpMaxTerminate            int      `json:"IpcpMaxTerminate,omitempty"`
			IpcpRestart                 int      `json:"IpcpRestart,omitempty"`
			IpcpTermRestart             int      `json:"IpcpTermRestart,omitempty"`
			LCPEcho                     int      `json:"LCPEcho,omitempty"`
			LCPEchoRetry                int      `json:"LCPEchoRetry,omitempty"`
			LastChange                  int      `json:"LastChange,omitempty"`
			LastConnectionError         string   `json:"LastConnectionError,omitempty"`
			LastStatsReset              int      `json:"LastStatsReset,omitempty"`
			LcpMaxConfigure             int      `json:"LcpMaxConfigure,omitempty"`
			LcpMaxTerminate             int      `json:"LcpMaxTerminate,omitempty"`
			LcpRestart                  int      `json:"LcpRestart,omitempty"`
			LcpTermRestart              int      `json:"LcpTermRestart,omitempty"`
			LowerLayers                 string   `json:"LowerLayers,omitempty"`
			MaxFail                     int      `json:"MaxFail,omitempty"`
			MaxMRUSize                  int      `json:"MaxMRUSize,omitempty"`
			Name                        string   `json:"Name,omitempty"`
			NoCCP                       bool     `json:"NoCCP,omitempty"`
			PPPoA                       struct{} `json:"PPPoA,omitempty"`
			PPPoE                       struct {
				ACName              string `json:"ACName,omitempty"`
				OldPPPoESessionOpen string `json:"OldPPPoESessionOpen,omitempty"`
				RemoteMac           string `json:"RemoteMac,omitempty"`
				ServiceName         string `json:"ServiceName,omitempty"`
				SessionID           int    `json:"SessionID,omitempty"`
			} `json:"PPPoE,omitempty"`
			PPPoEMaxPadi                 int    `json:"PPPoEMaxPadi,omitempty"`
			PPPoEMaxPadiInterval         int    `json:"PPPoEMaxPadiInterval,omitempty"`
			PPPoEPadi1StRandom           bool   `json:"PPPoEPadi1stRandom,omitempty"`
			PPPoEPadiInterval            int    `json:"PPPoEPadiInterval,omitempty"`
			PPPoEPadrInterval            int    `json:"PPPoEPadrInterval,omitempty"`
			PPPoEPadrIntervalStatic      bool   `json:"PPPoEPadrIntervalStatic,omitempty"`
			PPPoEUseMaxPadiAfterSrvError bool   `json:"PPPoEUseMaxPadiAfterSrvError,omitempty"`
			PapMaxAuthReq                int    `json:"PapMaxAuthReq,omitempty"`
			PapRestart                   int    `json:"PapRestart,omitempty"`
			Password                     string `json:"Password,omitempty"`
			PeerAuth                     struct {
				AuthType string `json:"AuthType,omitempty"`
				Chap     string `json:"Chap,omitempty"`
				Eap      string `json:"Eap,omitempty"`
				MsChap   string `json:"MsChap,omitempty"`
				MsChapV2 string `json:"MsChapV2,omitempty"`
				Pap      string `json:"Pap,omitempty"`
			} `json:"PeerAuth,omitempty"`
			Reset      bool   `json:"Reset,omitempty"`
			ResetStats bool   `json:"ResetStats,omitempty"`
			SMUState   string `json:"SMUState,omitempty"`
			SelfAuth   struct {
				Chap     string `json:"Chap,omitempty"`
				Eap      string `json:"Eap,omitempty"`
				MsChap   string `json:"MsChap,omitempty"`
				MsChapV2 string `json:"MsChapV2,omitempty"`
				Pap      string `json:"Pap,omitempty"`
			} `json:"SelfAuth,omitempty"`
			Stats struct {
				BroadcastPacketsReceived    string `json:"BroadcastPacketsReceived,omitempty"`
				BroadcastPacketsSent        string `json:"BroadcastPacketsSent,omitempty"`
				BytesReceived               string `json:"BytesReceived,omitempty"`
				BytesSent                   string `json:"BytesSent,omitempty"`
				CollisionsPackets           int    `json:"CollisionsPackets,omitempty"`
				DiscardPacketsReceived      int    `json:"DiscardPacketsReceived,omitempty"`
				DiscardPacketsSent          int    `json:"DiscardPacketsSent,omitempty"`
				ErrorsReceived              int    `json:"ErrorsReceived,omitempty"`
				ErrorsSent                  int    `json:"ErrorsSent,omitempty"`
				MulticastPacketsReceived    string `json:"MulticastPacketsReceived,omitempty"`
				MulticastPacketsSent        string `json:"MulticastPacketsSent,omitempty"`
				PacketsReceived             string `json:"PacketsReceived,omitempty"`
				PacketsSent                 string `json:"PacketsSent,omitempty"`
				RetransCount                int    `json:"RetransCount,omitempty"`
				UnicastPacketsReceived      string `json:"UnicastPacketsReceived,omitempty"`
				UnicastPacketsSent          string `json:"UnicastPacketsSent,omitempty"`
				UnknownProtoPacketsReceived int    `json:"UnknownProtoPacketsReceived,omitempty"`
			} `json:"Stats,omitempty"`
			Status              string `json:"Status,omitempty"`
			StoppedBy           string `json:"StoppedBy,omitempty"`
			SupportedNCPs       string `json:"SupportedNCPs,omitempty"`
			TransportType       string `json:"TransportType,omitempty"`
			UnitNumber          int    `json:"UnitNumber,omitempty"`
			UseRandom1StHoldoff bool   `json:"UseRandom1stHoldoff,omitempty"`
			Username            string `json:"Username,omitempty"`
			WarnDisconnectDelay int    `json:"WarnDisconnectDelay,omitempty"`
			UID                 int    `json:"uid,omitempty"`
		} `json:"Interfaces,omitempty"`
		SupportedNCPs string `json:"SupportedNCPs,omitempty"`
	} `json:"PPP,omitempty"`
	PeriodicStatistics struct {
		MaxReportSamples  int   `json:"MaxReportSamples,omitempty"`
		MinSampleInterval int   `json:"MinSampleInterval,omitempty"`
		SampleSets        []any `json:"SampleSets,omitempty"`
	} `json:"PeriodicStatistics,omitempty"`
	RestoreInfo struct {
		AvailableBackups []any `json:"AvailableBackups,omitempty"`
		BackupInfo       struct {
			LastDailyBackup   string `json:"LastDailyBackup,omitempty"`
			LastManualBackup  string `json:"LastManualBackup,omitempty"`
			LastMonthlyBackup string `json:"LastMonthlyBackup,omitempty"`
			LastWeeklyBackup  string `json:"LastWeeklyBackup,omitempty"`
		} `json:"BackupInfo,omitempty"`
		FileFieldName  string `json:"FileFieldName,omitempty"`
		LastRestore    string `json:"LastRestore,omitempty"`
		URLKOFieldName string `json:"UrlKOFieldName,omitempty"`
		URLOKFieldName string `json:"UrlOKFieldName,omitempty"`
		URLRestore     string `json:"UrlRestore,omitempty"`
	} `json:"RestoreInfo,omitempty"`
	RootDataModelVersion string `json:"RootDataModelVersion,omitempty"`
	RouterAdvertisement  struct {
		Enable            bool `json:"Enable,omitempty"`
		InterfaceSettings []struct {
			AdvCurHopLimit             int    `json:"AdvCurHopLimit,omitempty"`
			AdvDefaultLifetime         int    `json:"AdvDefaultLifetime,omitempty"`
			AdvLinkMTU                 int    `json:"AdvLinkMTU,omitempty"`
			AdvManagedFlag             bool   `json:"AdvManagedFlag,omitempty"`
			AdvMobileAgentFlag         bool   `json:"AdvMobileAgentFlag,omitempty"`
			AdvNDProxyFlag             bool   `json:"AdvNDProxyFlag,omitempty"`
			AdvOtherConfigFlag         bool   `json:"AdvOtherConfigFlag,omitempty"`
			AdvPreferredRouterFlag     string `json:"AdvPreferredRouterFlag,omitempty"`
			AdvReachableTime           int    `json:"AdvReachableTime,omitempty"`
			AdvRetransTimer            int    `json:"AdvRetransTimer,omitempty"`
			Alias                      string `json:"Alias,omitempty"`
			Enable                     bool   `json:"Enable,omitempty"`
			Interface                  string `json:"Interface,omitempty"`
			ManualPrefixes             string `json:"ManualPrefixes,omitempty"`
			MaxRtrAdvInterval          int    `json:"MaxRtrAdvInterval,omitempty"`
			MinRtrAdvInterval          int    `json:"MinRtrAdvInterval,omitempty"`
			NeighAdvertisementInterval int    `json:"NeighAdvertisementInterval,omitempty"`
			Options                    []struct {
				Alias  string `json:"Alias,omitempty"`
				Enable bool   `json:"Enable,omitempty"`
				Tag    int    `json:"Tag,omitempty"`
				Value  string `json:"Value,omitempty"`
				UID    int    `json:"uid,omitempty"`
			} `json:"Options,omitempty"`
			Prefixes string `json:"Prefixes,omitempty"`
			Status   string `json:"Status,omitempty"`
			UID      int    `json:"uid,omitempty"`
		} `json:"InterfaceSettings,omitempty"`
	} `json:"RouterAdvertisement,omitempty"`
	Routing struct {
		Rip struct {
			Enable                            bool   `json:"Enable,omitempty"`
			InterfaceSettings                 []any  `json:"InterfaceSettings,omitempty"`
			Redistribute                      string `json:"Redistribute,omitempty"`
			SupportedModes                    string `json:"SupportedModes,omitempty"`
			XSAGEMCOMAdvertisementInterval    int    `json:"X_SAGEMCOM_AdvertisementInterval,omitempty"`
			XSAGEMCOMRIPIPPrefix              []any  `json:"X_SAGEMCOM_RIPIPPrefix,omitempty"`
			XSAGEMCOMRIPNATRoutedSubnetEnable bool   `json:"X_SAGEMCOM_RIPNATRoutedSubnetEnable,omitempty"`
		} `json:"RIP,omitempty"`
		RouteInformation struct {
			Enable            bool  `json:"Enable,omitempty"`
			InterfaceSettings []any `json:"InterfaceSettings,omitempty"`
		} `json:"RouteInformation,omitempty"`
		Routers []struct {
			Alias           string `json:"Alias,omitempty"`
			DefaultRouter   bool   `json:"DefaultRouter,omitempty"`
			Enable          bool   `json:"Enable,omitempty"`
			IPv4Forwardings []struct {
				Alias            string `json:"Alias,omitempty"`
				DestIPAddress    string `json:"DestIPAddress,omitempty"`
				DestSubnetMask   string `json:"DestSubnetMask,omitempty"`
				DeviceName       string `json:"DeviceName,omitempty"`
				Enable           bool   `json:"Enable,omitempty"`
				ForwardingMetric int    `json:"ForwardingMetric,omitempty"`
				ForwardingPolicy int    `json:"ForwardingPolicy,omitempty"`
				GatewayIPAddress string `json:"GatewayIPAddress,omitempty"`
				Interface        string `json:"Interface,omitempty"`
				NbRef            int    `json:"NbRef,omitempty"`
				Origin           string `json:"Origin,omitempty"`
				Source           string `json:"Source,omitempty"`
				StaticRoute      bool   `json:"StaticRoute,omitempty"`
				Status           string `json:"Status,omitempty"`
				UID              int    `json:"uid,omitempty"`
			} `json:"IPv4Forwardings,omitempty"`
			IPv6Forwardings []any  `json:"IPv6Forwardings,omitempty"`
			Status          string `json:"Status,omitempty"`
			UID             int    `json:"uid,omitempty"`
		} `json:"Routers,omitempty"`
	} `json:"Routing,omitempty"`
	SelfTestDiagnostics struct {
		DiagnosticsState string `json:"DiagnosticsState,omitempty"`
		Results          string `json:"Results,omitempty"`
	} `json:"SelfTestDiagnostics,omitempty"`
	Services struct {
		Activation struct {
			RequestCount int `json:"RequestCount,omitempty"`
		} `json:"Activation,omitempty"`
		BellBandwidthMonitoring struct {
			BillingDay          int    `json:"BillingDay,omitempty"`
			CurrentDate         string `json:"CurrentDate,omitempty"`
			DateList            string `json:"DateList,omitempty"`
			HostNumberOfEntries int    `json:"HostNumberOfEntries,omitempty"`
			Hosts               []any  `json:"Hosts,omitempty"`
			PreviousDate        string `json:"PreviousDate,omitempty"`
			RetentionPeriod     int    `json:"RetentionPeriod,omitempty"`
			Stats               struct {
				CurrentDayReceived  int    `json:"CurrentDayReceived,omitempty"`
				CurrentDaySent      int    `json:"CurrentDaySent,omitempty"`
				PreviousDayReceived int    `json:"PreviousDayReceived,omitempty"`
				PreviousDaySent     int    `json:"PreviousDaySent,omitempty"`
				ReceivedList        string `json:"ReceivedList,omitempty"`
				SentList            string `json:"SentList,omitempty"`
			} `json:"Stats,omitempty"`
		} `json:"BellBandwidthMonitoring,omitempty"`
		BellCredentialsRequestEmail struct {
			RequestCount int `json:"RequestCount,omitempty"`
		} `json:"BellCredentialsRequestEmail,omitempty"`
		BellIGMPStatistics struct {
			Enable                   bool  `json:"Enable,omitempty"`
			MessagesReceived         int   `json:"MessagesReceived,omitempty"`
			QueriesReceived          int   `json:"QueriesReceived,omitempty"`
			Stream                   []any `json:"Stream,omitempty"`
			V2LeaveMessagesReceived  int   `json:"V2LeaveMessagesReceived,omitempty"`
			V2ReportMessagesReceived int   `json:"V2ReportMessagesReceived,omitempty"`
			V3ReportMessagesReceived int   `json:"V3ReportMessagesReceived,omitempty"`
		} `json:"BellIGMPStatistics,omitempty"`
		BellInformationalEmail struct {
			ClearTextAuthEnable      bool   `json:"ClearTextAuthEnable,omitempty"`
			DestinationAddress       string `json:"DestinationAddress,omitempty"`
			Enable                   bool   `json:"Enable,omitempty"`
			SMTPPassword             string `json:"SMTPPassword,omitempty"`
			SMTPServerAddress        string `json:"SMTPServerAddress,omitempty"`
			SMTPUsername             string `json:"SMTPUsername,omitempty"`
			SecurePasswordAuthEnable bool   `json:"SecurePasswordAuthEnable,omitempty"`
		} `json:"BellInformationalEmail,omitempty"`
		BellNetworkCfg struct {
			AdvancedDMZ struct {
				AdvancedDMZhost string `json:"AdvancedDMZhost,omitempty"`
				Enable          bool   `json:"Enable,omitempty"`
				Status          string `json:"Status,omitempty"`
			} `json:"AdvancedDMZ,omitempty"`
			AutoSensingMode     string `json:"AutoSensingMode,omitempty"`
			BandwidthMonitoring struct {
				CollectingPeriod int    `json:"CollectingPeriod,omitempty"`
				Enable           bool   `json:"Enable,omitempty"`
				HistoryPeriod    int    `json:"HistoryPeriod,omitempty"`
				Status           string `json:"Status,omitempty"`
			} `json:"BandwidthMonitoring,omitempty"`
			ButtonOsmEnable             bool   `json:"ButtonOsmEnable,omitempty"`
			FirmwareRollback            bool   `json:"FirmwareRollback,omitempty"`
			FirmwareRollbackMinVersion  string `json:"FirmwareRollbackMinVersion,omitempty"`
			IPTVEnable                  bool   `json:"IPTVEnable,omitempty"`
			IPv6Allowed                 bool   `json:"IPv6Allowed,omitempty"`
			InterfaceType               string `json:"InterfaceType,omitempty"`
			KnownSTBMacAddresses        string `json:"KnownSTBMacAddresses,omitempty"`
			KnownVAPMacAddresses        string `json:"KnownVAPMacAddresses,omitempty"`
			LanOsmEnable                bool   `json:"LanOsmEnable,omitempty"`
			LedOsmEnable                bool   `json:"LedOsmEnable,omitempty"`
			ResetIPTVService            bool   `json:"ResetIPTVService,omitempty"`
			ResetInternetService        bool   `json:"ResetInternetService,omitempty"`
			ResetVoiceService           bool   `json:"ResetVoiceService,omitempty"`
			SSHEnable                   bool   `json:"SSHEnable,omitempty"`
			ScreenOsmEnable             bool   `json:"ScreenOsmEnable,omitempty"`
			SetBridgeMode               string `json:"SetBridgeMode,omitempty"`
			SetIPTVInterface            int    `json:"SetIPTVInterface,omitempty"`
			SetIPTVMode                 string `json:"SetIPTVMode,omitempty"`
			SetIVoIPInterface           string `json:"SetIVoIPInterface,omitempty"`
			SetInternetMode             string `json:"SetInternetMode,omitempty"`
			SetServicesMode             string `json:"SetServicesMode,omitempty"`
			TVOsmEnable                 bool   `json:"TVOsmEnable,omitempty"`
			TelnetEnable                bool   `json:"TelnetEnable,omitempty"`
			TemperatureMonitorOsmEnable bool   `json:"TemperatureMonitorOsmEnable,omitempty"`
			TemperatureMonitoring       struct {
				DisplayInUI                 bool   `json:"DisplayInUI,omitempty"`
				DisplayOnScreen             bool   `json:"DisplayOnScreen,omitempty"`
				ListFeaturesPreviousState   int    `json:"ListFeaturesPreviousState,omitempty"`
				ListFeaturesShutdown        int    `json:"ListFeaturesShutdown,omitempty"`
				Mode                        string `json:"Mode,omitempty"`
				RebootCountDown             int    `json:"RebootCountDown,omitempty"`
				Temperature                 int    `json:"Temperature,omitempty"`
				TemperatureMonitoringPeriod int    `json:"TemperatureMonitoringPeriod,omitempty"`
				Thresholds                  string `json:"Thresholds,omitempty"`
			} `json:"TemperatureMonitoring,omitempty"`
			VoiceAllowedWANModes string `json:"VoiceAllowedWANModes,omitempty"`
			VoiceEnable          bool   `json:"VoiceEnable,omitempty"`
			WANSSHBlockTimer     int    `json:"WANSSHBlockTimer,omitempty"`
			WANSSHSessionTimer   int    `json:"WANSSHSessionTimer,omitempty"`
			WanMode              string `json:"WanMode,omitempty"`
			WanModeVoiceLock     bool   `json:"WanModeVoiceLock,omitempty"`
			WanType              string `json:"WanType,omitempty"`
		} `json:"BellNetworkCfg,omitempty"`
		BellPPPoEPassthrough struct {
			Client []any `json:"Client,omitempty"`
			Enable bool  `json:"Enable,omitempty"`
		} `json:"BellPPPoEPassthrough,omitempty"`
		CLIPassword string `json:"CLIPassword,omitempty"`
		DynamicDNS  struct {
			Clients []struct {
				Alias     string `json:"Alias,omitempty"`
				Enable    bool   `json:"Enable,omitempty"`
				Hidden    bool   `json:"Hidden,omitempty"`
				Hostnames []struct {
					LastIP     string `json:"LastIP,omitempty"`
					LastUpdate string `json:"LastUpdate,omitempty"`
					Name       string `json:"Name,omitempty"`
					Status     string `json:"Status,omitempty"`
					UID        int    `json:"uid,omitempty"`
				} `json:"Hostnames,omitempty"`
				Interface                  string `json:"Interface,omitempty"`
				LastError                  string `json:"LastError,omitempty"`
				Offline                    bool   `json:"Offline,omitempty"`
				Password                   string `json:"Password,omitempty"`
				RemoteApplicationHTTPSPort int    `json:"RemoteApplicationHTTPSPort,omitempty"`
				ServiceEnum                string `json:"ServiceEnum,omitempty"`
				ServiceReference           string `json:"ServiceReference,omitempty"`
				Status                     string `json:"Status,omitempty"`
				Username                   string `json:"Username,omitempty"`
				UID                        int    `json:"uid,omitempty"`
			} `json:"Clients,omitempty"`
			Services []struct {
				Authentication string `json:"Authentication,omitempty"`
				GUIName        string `json:"GUIName,omitempty"`
				MaxRetries     int    `json:"MaxRetries,omitempty"`
				Name           string `json:"Name,omitempty"`
				Request        string `json:"Request,omitempty"`
				RetryInterval  int    `json:"RetryInterval,omitempty"`
				Server         string `json:"Server,omitempty"`
				ServerPort     int    `json:"ServerPort,omitempty"`
				UpdateInterval int    `json:"UpdateInterval,omitempty"`
				UID            int    `json:"uid,omitempty"`
			} `json:"Services,omitempty"`
		} `json:"DynamicDNS,omitempty"`
		IPTVDNSStatus     bool `json:"IPTVDNSStatus,omitempty"`
		InternetDNSStatus bool `json:"InternetDNSStatus,omitempty"`
		Notification      struct {
			CellularFailoverCount              int    `json:"CellularFailoverCount,omitempty"`
			CellularFailoverNotificationEnable bool   `json:"CellularFailoverNotificationEnable,omitempty"`
			ContactDisplay                     bool   `json:"ContactDisplay,omitempty"`
			CredentialsRequestCount            int    `json:"CredentialsRequestCount,omitempty"`
			CredentialsRequestEnable           bool   `json:"CredentialsRequestEnable,omitempty"`
			DestinationEmailAddress            string `json:"DestinationEmailAddress,omitempty"`
			DestinationSMSNumber               string `json:"DestinationSMSNumber,omitempty"`
			DisplayOnScreen                    bool   `json:"DisplayOnScreen,omitempty"`
			Email                              bool   `json:"Email,omitempty"`
			EndOfLifeBatteryNotificationCount  int    `json:"EndOfLifeBatteryNotificationCount,omitempty"`
			EndOfLifeBatteryNotificationEnable bool   `json:"EndOfLifeBatteryNotificationEnable,omitempty"`
			IgnoreDisabled                     bool   `json:"IgnoreDisabled,omitempty"`
			IgnoreNullDestinationAddress       bool   `json:"IgnoreNullDestinationAddress,omitempty"`
			Sms                                bool   `json:"SMS,omitempty"`
		} `json:"Notification,omitempty"`
		Plume struct {
			CloudAddress   string `json:"CloudAddress,omitempty"`
			Enable         string `json:"Enable,omitempty"`
			LocationID     string `json:"LocationID,omitempty"`
			OVSDBPort      int    `json:"OVSDBPort,omitempty"`
			PlumeCloudPort string `json:"PlumeCloudPort,omitempty"`
			Restart        bool   `json:"Restart,omitempty"`
			SavedMode      string `json:"SavedMode,omitempty"`
			Status         int    `json:"Status,omitempty"`
			SyslogLevel    string `json:"SyslogLevel,omitempty"`
			WhiteList      string `json:"WhiteList,omitempty"`
		} `json:"Plume,omitempty"`
		Schedulers struct {
			Schedulers []any `json:"Schedulers,omitempty"`
		} `json:"Schedulers,omitempty"`
		ServicesDNSStatus bool `json:"ServicesDNSStatus,omitempty"`
		SetLEDState       bool `json:"SetLEDState,omitempty"`
		StorageServices   []struct {
			Capabilities struct {
				FTPCapable                bool   `json:"FTPCapable,omitempty"`
				HTTPCapable               bool   `json:"HTTPCapable,omitempty"`
				HTTPSCapable              bool   `json:"HTTPSCapable,omitempty"`
				HTTPWritable              bool   `json:"HTTPWritable,omitempty"`
				SFTPCapable               bool   `json:"SFTPCapable,omitempty"`
				SupportedFileSystemTypes  string `json:"SupportedFileSystemTypes,omitempty"`
				SupportedNetworkProtocols string `json:"SupportedNetworkProtocols,omitempty"`
				SupportedRaidTypes        string `json:"SupportedRaidTypes,omitempty"`
				VolumeEncryptionCapable   bool   `json:"VolumeEncryptionCapable,omitempty"`
			} `json:"Capabilities,omitempty"`
			DefaultLogicalVolumesName string `json:"DefaultLogicalVolumesName,omitempty"`
			Enable                    bool   `json:"Enable,omitempty"`
			FTPServer                 struct {
				AnonymousUser struct {
					Enable         bool   `json:"Enable,omitempty"`
					ReadOnlyAccess bool   `json:"ReadOnlyAccess,omitempty"`
					StartingFolder string `json:"StartingFolder,omitempty"`
				} `json:"AnonymousUser,omitempty"`
				Enable      bool   `json:"Enable,omitempty"`
				IdleTime    int    `json:"IdleTime,omitempty"`
				MaxNumUsers int    `json:"MaxNumUsers,omitempty"`
				PortNumber  int    `json:"PortNumber,omitempty"`
				Status      string `json:"Status,omitempty"`
			} `json:"FTPServer,omitempty"`
			HTTPSServer struct {
				AuthenticationReq  bool   `json:"AuthenticationReq,omitempty"`
				Enable             bool   `json:"Enable,omitempty"`
				HTTPWritingEnabled bool   `json:"HTTPWritingEnabled,omitempty"`
				IdleTime           int    `json:"IdleTime,omitempty"`
				MaxNumUsers        int    `json:"MaxNumUsers,omitempty"`
				PortNumber         int    `json:"PortNumber,omitempty"`
				Status             string `json:"Status,omitempty"`
			} `json:"HTTPSServer,omitempty"`
			HTTPServer struct {
				AuthenticationReq  bool   `json:"AuthenticationReq,omitempty"`
				Enable             bool   `json:"Enable,omitempty"`
				HTTPWritingEnabled bool   `json:"HTTPWritingEnabled,omitempty"`
				IdleTime           int    `json:"IdleTime,omitempty"`
				MaxNumUsers        int    `json:"MaxNumUsers,omitempty"`
				PortNumber         int    `json:"PortNumber,omitempty"`
				Status             string `json:"Status,omitempty"`
			} `json:"HTTPServer,omitempty"`
			LogicalVolumes []any `json:"LogicalVolumes,omitempty"`
			NetInfo        struct {
				DomainName string `json:"DomainName,omitempty"`
				HostName   string `json:"HostName,omitempty"`
			} `json:"NetInfo,omitempty"`
			NetworkServer struct {
				AFPEnable              bool `json:"AFPEnable,omitempty"`
				NFSEnable              bool `json:"NFSEnable,omitempty"`
				NetworkProtocolAuthReq bool `json:"NetworkProtocolAuthReq,omitempty"`
				SMBEnable              bool `json:"SMBEnable,omitempty"`
			} `json:"NetworkServer,omitempty"`
			PhysicalMediums []any `json:"PhysicalMediums,omitempty"`
			Printers        struct {
				Enable         bool  `json:"Enable,omitempty"`
				PrinterDevices []any `json:"PrinterDevices,omitempty"`
			} `json:"Printers,omitempty"`
			SFTPServer struct {
				Enable      bool   `json:"Enable,omitempty"`
				IdleTime    int    `json:"IdleTime,omitempty"`
				MaxNumUsers int    `json:"MaxNumUsers,omitempty"`
				PortNumber  int    `json:"PortNumber,omitempty"`
				Status      string `json:"Status,omitempty"`
			} `json:"SFTPServer,omitempty"`
			StorageArrays []any `json:"StorageArrays,omitempty"`
			UserAccounts  []any `json:"UserAccounts,omitempty"`
			UserGroups    []any `json:"UserGroups,omitempty"`
			UID           int   `json:"uid,omitempty"`
		} `json:"StorageServices,omitempty"`
		VoiceOnlyEnable bool `json:"VoiceOnlyEnable,omitempty"`
		VoiceServices   []struct {
			Alias   string `json:"Alias,omitempty"`
			Battery struct {
				CriticalBatteryNotificationEnable bool   `json:"CriticalBatteryNotificationEnable,omitempty"`
				Enable                            bool   `json:"Enable,omitempty"`
				LowBatteryNotificationEnable      bool   `json:"LowBatteryNotificationEnable,omitempty"`
				NotificationFile                  string `json:"NotificationFile,omitempty"`
				NotificationInterval              int    `json:"NotificationInterval,omitempty"`
			} `json:"Battery,omitempty"`
			CallControl struct {
				CallLogNumberOfEntries  int    `json:"CallLogNumberOfEntries,omitempty"`
				CallLogs                []any  `json:"CallLogs,omitempty"`
				IncomingMaps            []any  `json:"IncomingMaps,omitempty"`
				InterDigitTimerOpen     int    `json:"InterDigitTimerOpen,omitempty"`
				InterDigitTimerStd      int    `json:"InterDigitTimerStd,omitempty"`
				Mailboxs                []any  `json:"Mailboxs,omitempty"`
				MaxIncomingCallLogCount int    `json:"MaxIncomingCallLogCount,omitempty"`
				MaxOutgoingCallLogCount int    `json:"MaxOutgoingCallLogCount,omitempty"`
				NumberingPlans          []any  `json:"NumberingPlans,omitempty"`
				OutgoingMaps            []any  `json:"OutgoingMaps,omitempty"`
				TerminationDigit        string `json:"TerminationDigit,omitempty"`
			} `json:"CallControl,omitempty"`
			CallingNumber string `json:"CallingNumber,omitempty"`
			Capabilities  struct {
				ButtonMap               bool  `json:"ButtonMap,omitempty"`
				Codecs                  []any `json:"Codecs,omitempty"`
				DSCPCoupled             bool  `json:"DSCPCoupled,omitempty"`
				DigitMap                bool  `json:"DigitMap,omitempty"`
				EthernetTaggingCoupled  bool  `json:"EthernetTaggingCoupled,omitempty"`
				FaxPassThrough          bool  `json:"FaxPassThrough,omitempty"`
				FaxT38                  bool  `json:"FaxT38,omitempty"`
				FileBasedRingGeneration bool  `json:"FileBasedRingGeneration,omitempty"`
				FileBasedToneGeneration bool  `json:"FileBasedToneGeneration,omitempty"`
				H323                    struct {
					FastStart                 bool   `json:"FastStart,omitempty"`
					H235AuthenticationMethods string `json:"H235AuthenticationMethods,omitempty"`
				} `json:"H323,omitempty"`
				Mgcp struct {
					Extensions string `json:"Extensions,omitempty"`
				} `json:"MGCP,omitempty"`
				MaxLineCount               int    `json:"MaxLineCount,omitempty"`
				MaxProfileCount            int    `json:"MaxProfileCount,omitempty"`
				MaxSessionCount            int    `json:"MaxSessionCount,omitempty"`
				MaxSessionsPerLine         int    `json:"MaxSessionsPerLine,omitempty"`
				ModemPassThrough           bool   `json:"ModemPassThrough,omitempty"`
				NumberingPlan              bool   `json:"NumberingPlan,omitempty"`
				PSTNSoftSwitchOver         bool   `json:"PSTNSoftSwitchOver,omitempty"`
				PatternBasedRingGeneration bool   `json:"PatternBasedRingGeneration,omitempty"`
				PatternBasedToneGeneration bool   `json:"PatternBasedToneGeneration,omitempty"`
				Rtcp                       bool   `json:"RTCP,omitempty"`
				RTPRedundancy              bool   `json:"RTPRedundancy,omitempty"`
				Regions                    string `json:"Regions,omitempty"`
				RingDescriptionsEditable   bool   `json:"RingDescriptionsEditable,omitempty"`
				RingFileFormats            string `json:"RingFileFormats,omitempty"`
				RingGeneration             bool   `json:"RingGeneration,omitempty"`
				RingPatternEditable        bool   `json:"RingPatternEditable,omitempty"`
				Sip                        struct {
					EventSubscription          bool   `json:"EventSubscription,omitempty"`
					Extensions                 string `json:"Extensions,omitempty"`
					ResponseMap                bool   `json:"ResponseMap,omitempty"`
					Role                       string `json:"Role,omitempty"`
					TLSAuthenticationKeySizes  string `json:"TLSAuthenticationKeySizes,omitempty"`
					TLSAuthenticationProtocols string `json:"TLSAuthenticationProtocols,omitempty"`
					TLSEncryptionKeySizes      string `json:"TLSEncryptionKeySizes,omitempty"`
					TLSEncryptionProtocols     string `json:"TLSEncryptionProtocols,omitempty"`
					TLSKeyExchangeProtocols    string `json:"TLSKeyExchangeProtocols,omitempty"`
					Transports                 string `json:"Transports,omitempty"`
					URISchemes                 string `json:"URISchemes,omitempty"`
				} `json:"SIP,omitempty"`
				Srtp                     bool   `json:"SRTP,omitempty"`
				SRTPEncryptionKeySizes   string `json:"SRTPEncryptionKeySizes,omitempty"`
				SRTPKeyingMethods        string `json:"SRTPKeyingMethods,omitempty"`
				SignalingProtocols       string `json:"SignalingProtocols,omitempty"`
				ToneDescriptionsEditable bool   `json:"ToneDescriptionsEditable,omitempty"`
				ToneFileFormats          string `json:"ToneFileFormats,omitempty"`
				ToneGeneration           bool   `json:"ToneGeneration,omitempty"`
				VoicePortTests           bool   `json:"VoicePortTests,omitempty"`
			} `json:"Capabilities,omitempty"`
			Contacts          []any `json:"Contacts,omitempty"`
			Enable            bool  `json:"Enable,omitempty"`
			ExtensionProfiles []any `json:"ExtensionProfiles,omitempty"`
			IVR               struct {
				AlternativeShortNumber string `json:"AlternativeShortNumber,omitempty"`
				DayNightSchedule       struct {
					Enable              bool  `json:"Enable,omitempty"`
					ManagementNightDays []any `json:"ManagementNightDays,omitempty"`
				} `json:"DayNightSchedule,omitempty"`
				DirectCallRestrictionID int    `json:"DirectCallRestrictionID,omitempty"`
				ExternalNumber          string `json:"ExternalNumber,omitempty"`
				Keys                    []any  `json:"Keys,omitempty"`
				Name                    string `json:"Name,omitempty"`
				Number                  int    `json:"Number,omitempty"`
				RepeatDelay             string `json:"RepeatDelay,omitempty"`
				RepeatTime              string `json:"RepeatTime,omitempty"`
				RingbackEnable          bool   `json:"RingbackEnable,omitempty"`
			} `json:"IVR,omitempty"`
			Messages        []any `json:"Messages,omitempty"`
			NetworkProfiles []any `json:"NetworkProfiles,omitempty"`
			PhyInterfaces   []struct {
				Alias           string `json:"Alias,omitempty"`
				CallingFeatures struct {
					CallTransferEnable        bool `json:"CallTransferEnable,omitempty"`
					CallWaitingEnable         bool `json:"CallWaitingEnable,omitempty"`
					CallWaitingTimeout        int  `json:"CallWaitingTimeout,omitempty"`
					CallingFeatureEnable      bool `json:"CallingFeatureEnable,omitempty"`
					DoubleCallEnable          bool `json:"DoubleCallEnable,omitempty"`
					LocalAnnouncementEnable   bool `json:"LocalAnnouncementEnable,omitempty"`
					MWIEnable                 bool `json:"MWIEnable,omitempty"`
					XSAGEMCOMConferenceEnable bool `json:"X_SAGEMCOM_ConferenceEnable,omitempty"`
					XSAGEMCOMVMWIEnable       bool `json:"X_SAGEMCOM_VMWIEnable,omitempty"`
				} `json:"CallingFeatures,omitempty"`
				CodecLists []struct {
					EntryID   int    `json:"EntryID,omitempty"`
					FXSStatus string `json:"FXSStatus,omitempty"`
					UID       int    `json:"uid,omitempty"`
				} `json:"CodecLists,omitempty"`
				Description      string `json:"Description,omitempty"`
				FXSStatus        string `json:"FXSStatus,omitempty"`
				FlashhookEnable  bool   `json:"FlashhookEnable,omitempty"`
				ForceDTMFInband  bool   `json:"ForceDTMFInband,omitempty"`
				InterfaceID      int    `json:"InterfaceID,omitempty"`
				Number           string `json:"Number,omitempty"`
				OutGoingLine     string `json:"OutGoingLine,omitempty"`
				PhyInterfaceType string `json:"PhyInterfaceType,omitempty"`
				PhyPort          string `json:"PhyPort,omitempty"`
				Status           string `json:"Status,omitempty"`
				StatusTime       string `json:"StatusTime,omitempty"`
				Tests            struct {
					TestResult   string `json:"TestResult,omitempty"`
					TestSelector string `json:"TestSelector,omitempty"`
					TestState    string `json:"TestState,omitempty"`
				} `json:"Tests,omitempty"`
				XSagemcomDectusb struct {
					CurrentNbPP        int    `json:"CurrentNbPP,omitempty"`
					Enable             bool   `json:"Enable,omitempty"`
					Status             string `json:"Status,omitempty"`
					SubscriptionEnable string `json:"SubscriptionEnable,omitempty"`
				} `json:"X_SAGEMCOM_DECTUSB,omitempty"`
				XSagemcomDectFp struct {
					CipheringEnable        bool   `json:"CipheringEnable,omitempty"`
					ClockMastered          bool   `json:"ClockMastered,omitempty"`
					CurrentNbPP            int    `json:"CurrentNbPP,omitempty"`
					EepromVersion          string `json:"EepromVersion,omitempty"`
					Enable                 bool   `json:"Enable,omitempty"`
					EncryptionType         string `json:"EncryptionType,omitempty"`
					ErrorStatus            string `json:"ErrorStatus,omitempty"`
					FUPercent              int    `json:"FUPercent,omitempty"`
					FirmwareVersion        string `json:"FirmwareVersion,omitempty"`
					HardwareVersion        string `json:"HardwareVersion,omitempty"`
					InternalListMngtEnable bool   `json:"InternalListMngtEnable,omitempty"`
					MaxSupportedPP         int    `json:"MaxSupportedPP,omitempty"`
					NEMOEnable             bool   `json:"NEMOEnable,omitempty"`
					Pin                    string `json:"PIN,omitempty"`
					Rfpi                   string `json:"RFPI,omitempty"`
					RFPowerControl         string `json:"RFPowerControl,omitempty"`
					RepeaterSupportEnabled bool   `json:"RepeaterSupportEnabled,omitempty"`
					Reset                  bool   `json:"Reset,omitempty"`
					Standard               string `json:"Standard,omitempty"`
					Status                 string `json:"Status,omitempty"`
					SubscriptionEnable     string `json:"SubscriptionEnable,omitempty"`
					SubscriptionTimeout    int    `json:"SubscriptionTimeout,omitempty"`
				} `json:"X_SAGEMCOM_DECT_FP,omitempty"`
				XSagemcomDectPp struct {
					Control                                 string `json:"Control,omitempty"`
					EMCforSUOTA                             int    `json:"EMCforSUOTA,omitempty"`
					HandsetRole                             string `json:"HandsetRole,omitempty"`
					HandsetType                             string `json:"HandsetType,omitempty"`
					HardwareVersion                         string `json:"HardwareVersion,omitempty"`
					InternationalPortableEquipementIdentity string `json:"InternationalPortableEquipementIdentity,omitempty"`
					InternationalPortableUserIdentity       string `json:"InternationalPortableUserIdentity,omitempty"`
					LastUpdateDateTime                      string `json:"LastUpdateDateTime,omitempty"`
					PortableAccessRightsKey                 string `json:"PortableAccessRightsKey,omitempty"`
					RFPIAttachedTo                          string `json:"RFPIAttachedTo,omitempty"`
					SoftwareUpgrade                         bool   `json:"SoftwareUpgrade,omitempty"`
					SoftwareVersion                         string `json:"SoftwareVersion,omitempty"`
					Status                                  string `json:"Status,omitempty"`
					SubscriptionTime                        string `json:"SubscriptionTime,omitempty"`
				} `json:"X_SAGEMCOM_DECT_PP,omitempty"`
				XSagemcomFxs struct {
					CallerIDDateTimeEnable bool `json:"CallerIdDateTimeEnable,omitempty"`
					EchoCancellationEnable bool `json:"EchoCancellationEnable,omitempty"`
					ReceiveGain            int  `json:"ReceiveGain,omitempty"`
					TransmitGain           int  `json:"TransmitGain,omitempty"`
				} `json:"X_SAGEMCOM_FXS,omitempty"`
				UID int `json:"uid,omitempty"`
			} `json:"PhyInterfaces,omitempty"`
			RegionalOptions []any `json:"RegionalOptions,omitempty"`
			SIP             struct {
				RegistrarNumberOfEntries int   `json:"RegistrarNumberOfEntries,omitempty"`
				Registrars               []any `json:"Registrars,omitempty"`
			} `json:"SIP,omitempty"`
			Tone struct {
				Descriptions []any `json:"Descriptions,omitempty"`
			} `json:"Tone,omitempty"`
			VoIPProfiles []any `json:"VoIPProfiles,omitempty"`
			VoiceMail    struct {
				MaxAccess       int    `json:"MaxAccess,omitempty"`
				Number          int    `json:"Number,omitempty"`
				NumberRemoteExt string `json:"NumberRemoteExt,omitempty"`
				NumberRemoteInt int    `json:"NumberRemoteInt,omitempty"`
				SMTP            struct {
					From     string `json:"From,omitempty"`
					Login    string `json:"Login,omitempty"`
					Password string `json:"Password,omitempty"`
					Server   string `json:"Server,omitempty"`
				} `json:"SMTP,omitempty"`
			} `json:"VoiceMail,omitempty"`
			VoiceProfiles []struct {
				BackupInterfaceSwitchCounter int `json:"BackupInterfaceSwitchCounter,omitempty"`
				ButtonMap                    struct {
					Buttons         []any `json:"Buttons,omitempty"`
					NumberOfButtons int   `json:"NumberOfButtons,omitempty"`
				} `json:"ButtonMap,omitempty"`
				DTMFMethod     string `json:"DTMFMethod,omitempty"`
				DTMFMethodG711 string `json:"DTMFMethodG711,omitempty"`
				DigitMapEnable bool   `json:"DigitMapEnable,omitempty"`
				DigitMaps      []any  `json:"DigitMaps,omitempty"`
				Emergency      struct {
					AutoRingBackEnable            bool   `json:"AutoRingBackEnable,omitempty"`
					BlockCallingFeaturesEnable    bool   `json:"BlockCallingFeaturesEnable,omitempty"`
					CalledPartyHoldEnable         bool   `json:"CalledPartyHoldEnable,omitempty"`
					CalledPartyHoldTimer          int    `json:"CalledPartyHoldTimer,omitempty"`
					DigitMap                      string `json:"DigitMap,omitempty"`
					Enable                        bool   `json:"Enable,omitempty"`
					EnhancedCalledPartyHoldEnable bool   `json:"EnhancedCalledPartyHoldEnable,omitempty"`
					EnhancedCalledPartyHoldTimer  int    `json:"EnhancedCalledPartyHoldTimer,omitempty"`
				} `json:"Emergency,omitempty"`
				Enable                    string `json:"Enable,omitempty"`
				FQDNServerNumberOfEntries int    `json:"FQDNServerNumberOfEntries,omitempty"`
				FQDNServers               []any  `json:"FQDNServers,omitempty"`
				FaxPassThrough            string `json:"FaxPassThrough,omitempty"`
				FaxT38                    struct {
					BitRate             int    `json:"BitRate,omitempty"`
					ECMTransport        bool   `json:"ECMTransport,omitempty"`
					Enable              bool   `json:"Enable,omitempty"`
					HighSpeedPacketRate int    `json:"HighSpeedPacketRate,omitempty"`
					HighSpeedRedundancy int    `json:"HighSpeedRedundancy,omitempty"`
					LowSpeedRedundancy  int    `json:"LowSpeedRedundancy,omitempty"`
					TCFMethod           string `json:"TCFMethod,omitempty"`
				} `json:"FaxT38,omitempty"`
				LastBackupInterfaceTime string `json:"LastBackupInterfaceTime,omitempty"`
				Lines                   []struct {
					CallState       string `json:"CallState,omitempty"`
					CallingFeatures struct {
						AnonymousCalEnable                bool   `json:"AnonymousCalEnable,omitempty"`
						AnonymousCallBlockEnable          bool   `json:"AnonymousCallBlockEnable,omitempty"`
						BlindCallTransferEnable           bool   `json:"BlindCallTransferEnable,omitempty"`
						CallDeclineEnable                 bool   `json:"CallDeclineEnable,omitempty"`
						CallForwardOnBusyActCode          string `json:"CallForwardOnBusyActCode,omitempty"`
						CallForwardOnBusyDeactCode        string `json:"CallForwardOnBusyDeactCode,omitempty"`
						CallForwardOnBusyEnable           bool   `json:"CallForwardOnBusyEnable,omitempty"`
						CallForwardOnBusyNumber           string `json:"CallForwardOnBusyNumber,omitempty"`
						CallForwardOnNoAnswerActCode      string `json:"CallForwardOnNoAnswerActCode,omitempty"`
						CallForwardOnNoAnswerDeactCode    string `json:"CallForwardOnNoAnswerDeactCode,omitempty"`
						CallForwardOnNoAnswerEnable       bool   `json:"CallForwardOnNoAnswerEnable,omitempty"`
						CallForwardOnNoAnswerNumber       string `json:"CallForwardOnNoAnswerNumber,omitempty"`
						CallForwardOnNoAnswerRingCount    int    `json:"CallForwardOnNoAnswerRingCount,omitempty"`
						CallForwardUnconditionalActCode   string `json:"CallForwardUnconditionalActCode,omitempty"`
						CallForwardUnconditionalDeactCode string `json:"CallForwardUnconditionalDeactCode,omitempty"`
						CallForwardUnconditionalEnable    bool   `json:"CallForwardUnconditionalEnable,omitempty"`
						CallForwardUnconditionalNumber    string `json:"CallForwardUnconditionalNumber,omitempty"`
						CallParkingEnable                 bool   `json:"CallParkingEnable,omitempty"`
						CallParkingMode                   string `json:"CallParkingMode,omitempty"`
						CallParkingTimeout                int    `json:"CallParkingTimeout,omitempty"`
						CallReturnEnable                  bool   `json:"CallReturnEnable,omitempty"`
						CallTransferEnable                bool   `json:"CallTransferEnable,omitempty"`
						CallWaitingEnable                 bool   `json:"CallWaitingEnable,omitempty"`
						CallWaitingStatus                 string `json:"CallWaitingStatus,omitempty"`
						CallWaitingTimeout                int    `json:"CallWaitingTimeout,omitempty"`
						CallerIDEnable                    bool   `json:"CallerIDEnable,omitempty"`
						CallerIDName                      string `json:"CallerIDName,omitempty"`
						CallerIDNameEnable                bool   `json:"CallerIDNameEnable,omitempty"`
						ConferenceCallingSessionCount     int    `json:"ConferenceCallingSessionCount,omitempty"`
						ConferenceCallingStatus           string `json:"ConferenceCallingStatus,omitempty"`
						DNDNbCallAttempts                 int    `json:"DND_NbCallAttempts,omitempty"`
						DNDNoActivityTimeout              int    `json:"DND_NoActivityTimeout,omitempty"`
						DoNotDisturbEnable                bool   `json:"DoNotDisturbEnable,omitempty"`
						DoubleCallEnable                  bool   `json:"DoubleCallEnable,omitempty"`
						HotLineEnable                     bool   `json:"HotLineEnable,omitempty"`
						HotLineWarmLineURI                string `json:"HotLineWarmLineURI,omitempty"`
						MWIEnable                         bool   `json:"MWIEnable,omitempty"`
						MaxSessions                       int    `json:"MaxSessions,omitempty"`
						MessageWaiting                    bool   `json:"MessageWaiting,omitempty"`
						MultiCallEnable                   bool   `json:"MultiCallEnable,omitempty"`
						OutgoingCallEnable                bool   `json:"OutgoingCallEnable,omitempty"`
						PermanentCLIRActCode              string `json:"PermanentCLIRActCode,omitempty"`
						PermanentCLIRDeactCode            string `json:"PermanentCLIRDeactCode,omitempty"`
						PermanentCLIREnable               bool   `json:"PermanentCLIREnable,omitempty"`
						RepeatDialEnable                  bool   `json:"RepeatDialEnable,omitempty"`
						WarmLineActCode                   string `json:"WarmLineActCode,omitempty"`
						WarmLineDeactCode                 string `json:"WarmLineDeactCode,omitempty"`
						WarmLineEnable                    bool   `json:"WarmLineEnable,omitempty"`
						WarmLineTimeout                   int    `json:"WarmLineTimeout,omitempty"`
						XSAGEMCOMCLIPEnable               bool   `json:"X_SAGEMCOM_CLIPEnable,omitempty"`
						XSAGEMCOMCNIPEnable               bool   `json:"X_SAGEMCOM_CNIPEnable,omitempty"`
						XSAGEMCOMConferenceEnable         bool   `json:"X_SAGEMCOM_ConferenceEnable,omitempty"`
						XSAGEMCOMVMWIEnable               bool   `json:"X_SAGEMCOM_VMWIEnable,omitempty"`
					} `json:"CallingFeatures,omitempty"`
					Codec struct {
						Lists []struct {
							BitRate                      int    `json:"BitRate,omitempty"`
							Codec                        string `json:"Codec,omitempty"`
							Enable                       bool   `json:"Enable,omitempty"`
							EntryID                      int    `json:"EntryID,omitempty"`
							PacketizationPeriod          string `json:"PacketizationPeriod,omitempty"`
							PreferredPacketisationPeriod int    `json:"PreferredPacketisationPeriod,omitempty"`
							Priority                     int    `json:"Priority,omitempty"`
							SilenceSuppression           bool   `json:"SilenceSuppression,omitempty"`
							UID                          int    `json:"uid,omitempty"`
						} `json:"Lists,omitempty"`
						ReceiveBitRate              int    `json:"ReceiveBitRate,omitempty"`
						ReceiveCodec                string `json:"ReceiveCodec,omitempty"`
						ReceiveSilenceSuppression   bool   `json:"ReceiveSilenceSuppression,omitempty"`
						TransmitBitRate             int    `json:"TransmitBitRate,omitempty"`
						TransmitCodec               string `json:"TransmitCodec,omitempty"`
						TransmitPacketizationPeriod int    `json:"TransmitPacketizationPeriod,omitempty"`
						TransmitSilenceSuppression  bool   `json:"TransmitSilenceSuppression,omitempty"`
					} `json:"Codec,omitempty"`
					DirectoryNumber  string `json:"DirectoryNumber,omitempty"`
					Enable           string `json:"Enable,omitempty"`
					ErrorCode        string `json:"ErrorCode,omitempty"`
					LineID           int    `json:"LineId,omitempty"`
					Name             string `json:"Name,omitempty"`
					PhyReferenceList string `json:"PhyReferenceList,omitempty"`
					RingMuteStatus   bool   `json:"RingMuteStatus,omitempty"`
					RingVolumeStatus int    `json:"RingVolumeStatus,omitempty"`
					Ringer           struct {
						Descriptions []struct {
							EntryID     int    `json:"EntryID,omitempty"`
							RingEnable  bool   `json:"RingEnable,omitempty"`
							RingFile    string `json:"RingFile,omitempty"`
							RingName    string `json:"RingName,omitempty"`
							RingPattern int    `json:"RingPattern,omitempty"`
							UID         int    `json:"uid,omitempty"`
						} `json:"Descriptions,omitempty"`
						Events   []any `json:"Events,omitempty"`
						Patterns []any `json:"Patterns,omitempty"`
					} `json:"Ringer,omitempty"`
					Sessions []any `json:"Sessions,omitempty"`
					Stats    struct {
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
						ResetStatistics                  bool   `json:"ResetStatistics,omitempty"`
						RoundTripDelay                   int    `json:"RoundTripDelay,omitempty"`
						ServerDownTime                   int    `json:"ServerDownTime,omitempty"`
						TotalCallTime                    int    `json:"TotalCallTime,omitempty"`
						Underruns                        int    `json:"Underruns,omitempty"`
						XSAGEMCOMLastCalledNumber        string `json:"X_SAGEMCOM_LastCalledNumber,omitempty"`
					} `json:"Stats,omitempty"`
					Status          string `json:"Status,omitempty"`
					StatusReason    string `json:"StatusReason,omitempty"`
					VoiceMail       string `json:"VoiceMail,omitempty"`
					VoiceProcessing struct {
						EchoCancellationEnable bool `json:"EchoCancellationEnable,omitempty"`
						EchoCancellationInUse  bool `json:"EchoCancellationInUse,omitempty"`
						EchoCancellationTail   int  `json:"EchoCancellationTail,omitempty"`
						ReceiveGain            int  `json:"ReceiveGain,omitempty"`
						TransmitGain           int  `json:"TransmitGain,omitempty"`
					} `json:"VoiceProcessing,omitempty"`
					XSAGEMCOMMaxSessions int `json:"X_SAGEMCOM_MaxSessions,omitempty"`
					UID                  int `json:"uid,omitempty"`
				} `json:"Lines,omitempty"`
				MaxSessions                         int    `json:"MaxSessions,omitempty"`
				ModemPassThrough                    string `json:"ModemPassThrough,omitempty"`
				Name                                string `json:"Name,omitempty"`
				NonVoiceBandwidthReservedDownstream int    `json:"NonVoiceBandwidthReservedDownstream,omitempty"`
				NonVoiceBandwidthReservedUpstream   int    `json:"NonVoiceBandwidthReservedUpstream,omitempty"`
				NumberOfLines                       int    `json:"NumberOfLines,omitempty"`
				NumberingPlan                       struct {
					FirstDigitTimer              int    `json:"FirstDigitTimer,omitempty"`
					FlashHookTimer               int    `json:"FlashHookTimer,omitempty"`
					InterDigitTimerOpen          int    `json:"InterDigitTimerOpen,omitempty"`
					InterDigitTimerStd           int    `json:"InterDigitTimerStd,omitempty"`
					InvalidNumberTone            int    `json:"InvalidNumberTone,omitempty"`
					MaximumNumberOfDigits        int    `json:"MaximumNumberOfDigits,omitempty"`
					MinimumNumberOfDigits        int    `json:"MinimumNumberOfDigits,omitempty"`
					PrefixInfos                  []any  `json:"PrefixInfos,omitempty"`
					XSAGEMCOMEndOfNumberingDigit string `json:"X_SAGEMCOM_EndOfNumberingDigit,omitempty"`
				} `json:"NumberingPlan,omitempty"`
				PLCMode             string `json:"PLCMode,omitempty"`
				PSTNFailOver        bool   `json:"PSTNFailOver,omitempty"`
				Region              string `json:"Region,omitempty"`
				Reset               bool   `json:"Reset,omitempty"`
				STUNEnable          bool   `json:"STUNEnable,omitempty"`
				STUNServer          string `json:"STUNServer,omitempty"`
				ServiceProviderInfo struct {
					ContactPhoneNumber string `json:"ContactPhoneNumber,omitempty"`
					EmailAddress       string `json:"EmailAddress,omitempty"`
					Name               string `json:"Name,omitempty"`
					URL                string `json:"URL,omitempty"`
				} `json:"ServiceProviderInfo,omitempty"`
				SignalingProtocol                string `json:"SignalingProtocol,omitempty"`
				Status                           string `json:"Status,omitempty"`
				VoiceBackupInterfaceEnable       bool   `json:"VoiceBackupInterfaceEnable,omitempty"`
				VoiceBackupInterfaceStatus       string `json:"VoiceBackupInterfaceStatus,omitempty"`
				VoiceBackupInterfaceStatusReason string `json:"VoiceBackupInterfaceStatusReason,omitempty"`
				UID                              int    `json:"uid,omitempty"`
			} `json:"VoiceProfiles,omitempty"`
			XSAGEMCOMDECTBaseEnable bool `json:"X_SAGEMCOM_DECTBaseEnable,omitempty"`
			XSAGEMCOMMaxLicense     int  `json:"X_SAGEMCOM_MaxLicense,omitempty"`
			XSAGEMCOMPSTNEnable     bool `json:"X_SAGEMCOM_PSTNEnable,omitempty"`
			XSAGEMCOMVoiceBehavior  struct {
				BackupInterface struct {
					FailOverInterfaceDownDuringCallTimer int `json:"FailOverInterfaceDownDuringCallTimer,omitempty"`
					FailOverInterfaceDownTimer           int `json:"FailOverInterfaceDownTimer,omitempty"`
					FailOverInviteNoRespTimer            int `json:"FailOverInviteNoRespTimer,omitempty"`
					FailOverRegisterNoRespTimer          int `json:"FailOverRegisterNoRespTimer,omitempty"`
				} `json:"BackupInterface,omitempty"`
				LocalAnnouncement struct {
					PauseDelayMs  int    `json:"PauseDelayMs,omitempty"`
					RepeatNumber  int    `json:"RepeatNumber,omitempty"`
					StartDelayMs  int    `json:"StartDelayMs,omitempty"`
					StopDigitList string `json:"StopDigitList,omitempty"`
				} `json:"LocalAnnouncement,omitempty"`
			} `json:"X_SAGEMCOM_VoiceBehavior,omitempty"`
			XSAGEMCOMVoiceManagement struct {
				AutoStart                      bool   `json:"AutoStart,omitempty"`
				BfProcessCertifMode            bool   `json:"BfProcessCertifMode,omitempty"`
				BfProcessDebugMode             bool   `json:"BfProcessDebugMode,omitempty"`
				BfProcessName                  string `json:"BfProcessName,omitempty"`
				BfProcessUnexpectedTerminateNb int    `json:"BfProcessUnexpectedTerminateNb,omitempty"`
				DataInterface                  string `json:"DataInterface,omitempty"`
				FxoInterface                   string `json:"FxoInterface,omitempty"`
				IP6Enable                      bool   `json:"IP6Enable,omitempty"`
				MonitoringEnable               bool   `json:"MonitoringEnable,omitempty"`
				UseOption120                   bool   `json:"UseOption120,omitempty"`
				VoiceCallEmergencyInProgress   bool   `json:"VoiceCallEmergencyInProgress,omitempty"`
				VoiceConfigLocked              bool   `json:"VoiceConfigLocked,omitempty"`
				VoiceServiceEnable             bool   `json:"VoiceServiceEnable,omitempty"`
				VoipBackupInterface            string `json:"VoipBackupInterface,omitempty"`
				VoipInterface                  string `json:"VoipInterface,omitempty"`
			} `json:"X_SAGEMCOM_VoiceManagement,omitempty"`
			UID int `json:"uid,omitempty"`
		} `json:"VoiceServices,omitempty"`
	} `json:"Services,omitempty"`
	Time struct {
		CurrentLocalTime      string `json:"CurrentLocalTime,omitempty"`
		DaylightSavingTime    string `json:"DaylightSavingTime,omitempty"`
		Enable                bool   `json:"Enable,omitempty"`
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
		NTPSyncInterval       int    `json:"NTPSyncInterval,omitempty"`
		Status                string `json:"Status,omitempty"`
	} `json:"Time,omitempty"`
	Tunneling struct {
		TunnelsL2 []any `json:"TunnelsL2,omitempty"`
	} `json:"Tunneling,omitempty"`
	UPA struct {
		Diagnostics struct {
			InterfaceMeasurement struct {
				DiagnosticsState string `json:"DiagnosticsState,omitempty"`
				Interface        string `json:"Interface,omitempty"`
				Measurements     string `json:"Measurements,omitempty"`
				Port             int    `json:"Port,omitempty"`
				RxGain           int    `json:"RxGain,omitempty"`
				Type             string `json:"Type,omitempty"`
			} `json:"InterfaceMeasurement,omitempty"`
		} `json:"Diagnostics,omitempty"`
		Interfaces []any `json:"Interfaces,omitempty"`
	} `json:"UPA,omitempty"`
	UPnP struct {
		Description struct {
			DeviceDescription []any `json:"DeviceDescription,omitempty"`
			DeviceInstance    []any `json:"DeviceInstance,omitempty"`
			ServiceInstance   []any `json:"ServiceInstance,omitempty"`
		} `json:"Description,omitempty"`
		Device struct {
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
			Enable   bool `json:"Enable,omitempty"`
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
		} `json:"Device,omitempty"`
		Discovery struct {
			Devices []struct {
				FriendlyName string `json:"FriendlyName,omitempty"`
				Host         string `json:"Host,omitempty"`
				LastUpdate   string `json:"LastUpdate,omitempty"`
				LeaseTime    int    `json:"LeaseTime,omitempty"`
				Location     string `json:"Location,omitempty"`
				Manufacturer string `json:"Manufacturer,omitempty"`
				MediaType    string `json:"MediaType,omitempty"`
				ModelName    string `json:"ModelName,omitempty"`
				Port         int    `json:"Port,omitempty"`
				Server       string `json:"Server,omitempty"`
				Status       string `json:"Status,omitempty"`
				Usn          string `json:"USN,omitempty"`
				UUID         string `json:"UUID,omitempty"`
				UserAgent    string `json:"UserAgent,omitempty"`
				UID          int    `json:"uid,omitempty"`
			} `json:"Devices,omitempty"`
			RootDevices []struct {
				Host       string `json:"Host,omitempty"`
				LastUpdate string `json:"LastUpdate,omitempty"`
				LeaseTime  int    `json:"LeaseTime,omitempty"`
				Location   string `json:"Location,omitempty"`
				Port       int    `json:"Port,omitempty"`
				Server     string `json:"Server,omitempty"`
				Status     string `json:"Status,omitempty"`
				Usn        string `json:"USN,omitempty"`
				UUID       string `json:"UUID,omitempty"`
				UserAgent  string `json:"UserAgent,omitempty"`
				UID        int    `json:"uid,omitempty"`
			} `json:"RootDevices,omitempty"`
			Services []struct {
				Host         string `json:"Host,omitempty"`
				LastUpdate   string `json:"LastUpdate,omitempty"`
				LeaseTime    int    `json:"LeaseTime,omitempty"`
				Location     string `json:"Location,omitempty"`
				ParentDevice string `json:"ParentDevice,omitempty"`
				Port         int    `json:"Port,omitempty"`
				Server       string `json:"Server,omitempty"`
				Status       string `json:"Status,omitempty"`
				Usn          string `json:"USN,omitempty"`
				UserAgent    string `json:"UserAgent,omitempty"`
				UID          int    `json:"uid,omitempty"`
			} `json:"Services,omitempty"`
		} `json:"Discovery,omitempty"`
		Settings struct {
			ExtendedUPnPSecurity bool   `json:"ExtendedUPnPSecurity,omitempty"`
			Instance             string `json:"Instance,omitempty"`
			LanInterface         string `json:"LanInterface,omitempty"`
			UPnP                 struct {
				TimeoutPolling int `json:"TimeoutPolling,omitempty"`
			} `json:"UPnP,omitempty"`
			UPnPIGD struct {
				AccessProvider        string `json:"AccessProvider,omitempty"`
				AdvertisementInterval int    `json:"AdvertisementInterval,omitempty"`
				AdvertisementTTL      int    `json:"AdvertisementTTL,omitempty"`
				AuthorizationEnable   bool   `json:"AuthorizationEnable,omitempty"`
				DebugLevel            string `json:"DebugLevel,omitempty"`
				DefaultDuration       int    `json:"DefaultDuration,omitempty"`
				DefaultHTTPSPort      int    `json:"DefaultHttpsPort,omitempty"`
				IGDRelease            string `json:"IGDRelease,omitempty"`
				InternetGatewayDevice struct {
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
				Layer3ForwardingEnable string `json:"Layer3ForwardingEnable,omitempty"`
				MaxRulesNumber         int    `json:"MaxRulesNumber,omitempty"`
				PnPX                   struct {
					CompatibleID       string `json:"CompatibleId,omitempty"`
					DfDeviceCategory   string `json:"DfDeviceCategory,omitempty"`
					Did                string `json:"Did,omitempty"`
					Enable             bool   `json:"Enable,omitempty"`
					PnpxDeviceCategory string `json:"PnpxDeviceCategory,omitempty"`
					Rid                string `json:"Rid,omitempty"`
					Sid                string `json:"Sid,omitempty"`
					Vid                string `json:"Vid,omitempty"`
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
					Enable      bool   `json:"Enable,omitempty"`
					EventEnable bool   `json:"EventEnable,omitempty"`
					Interface   string `json:"Interface,omitempty"`
					UID         int    `json:"uid,omitempty"`
				} `json:"WanInterfaces,omitempty"`
				WithIcon bool `json:"WithIcon,omitempty"`
			} `json:"UPnPIGD,omitempty"`
			UPnPMediaServer struct {
				AccessPwd    string `json:"AccessPwd,omitempty"`
				AccessUser   string `json:"AccessUser,omitempty"`
				AdaptCase    string `json:"AdaptCase,omitempty"`
				Aggmode      string `json:"Aggmode,omitempty"`
				Aggregation  bool   `json:"Aggregation,omitempty"`
				AllName      string `json:"AllName,omitempty"`
				AllPictures  string `json:"AllPictures,omitempty"`
				AllRadio     string `json:"AllRadio,omitempty"`
				AllTracks    string `json:"AllTracks,omitempty"`
				AllVideos    string `json:"AllVideos,omitempty"`
				AutoTree     string `json:"AutoTree,omitempty"`
				CacheMaxSize string `json:"CacheMaxSize,omitempty"`
				ContentDir   string `json:"ContentDir,omitempty"`
				DbDir        string `json:"DbDir,omitempty"`
				FolderNodes  []struct {
					Attributes string `json:"Attributes,omitempty"`
					UID        int    `json:"uid,omitempty"`
				} `json:"FolderNodes,omitempty"`
				FriendlyName  string `json:"FriendlyName,omitempty"`
				InternetRadio string `json:"InternetRadio,omitempty"`
				Language      string `json:"Language,omitempty"`
				MaxCount      string `json:"MaxCount,omitempty"`
				MaxMedia      string `json:"MaxMedia,omitempty"`
				MaxMem        string `json:"MaxMem,omitempty"`
				MusicNodes    []struct {
					Attributes string `json:"Attributes,omitempty"`
					UID        int    `json:"uid,omitempty"`
				} `json:"MusicNodes,omitempty"`
				PictureNodes []struct {
					Attributes string `json:"Attributes,omitempty"`
					UID        int    `json:"uid,omitempty"`
				} `json:"PictureNodes,omitempty"`
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
				UPnPMediaServerPort          int    `json:"UPnPMediaServerPort,omitempty"`
				UPnPMediaServerVersionNumber string `json:"UPnPMediaServerVersionNumber,omitempty"`
				UPnPNMCServer                bool   `json:"UPnPNMCServer,omitempty"`
				UploadEnabled                string `json:"UploadEnabled,omitempty"`
				Verbose                      string `json:"Verbose,omitempty"`
				VideoNodes                   []struct {
					Attributes string `json:"Attributes,omitempty"`
					UID        int    `json:"uid,omitempty"`
				} `json:"VideoNodes,omitempty"`
			} `json:"UPnPMediaServer,omitempty"`
		} `json:"Settings,omitempty"`
	} `json:"UPnP,omitempty"`
	USB struct {
		Enable     bool  `json:"Enable,omitempty"`
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
		USBHosts struct {
			Hosts []struct {
				Alias                 string `json:"Alias,omitempty"`
				Devices               []any  `json:"Devices,omitempty"`
				Enable                bool   `json:"Enable,omitempty"`
				Name                  string `json:"Name,omitempty"`
				PowerManagementEnable bool   `json:"PowerManagementEnable,omitempty"`
				Reset                 bool   `json:"Reset,omitempty"`
				Type                  string `json:"Type,omitempty"`
				USBVersion            string `json:"USBVersion,omitempty"`
				UID                   int    `json:"uid,omitempty"`
			} `json:"Hosts,omitempty"`
		} `json:"USBHosts,omitempty"`
	} `json:"USB,omitempty"`
	UserAccounts struct {
		LANInterface string `json:"LANInterface,omitempty"`
		MNGInterface string `json:"MNGInterface,omitempty"`
		Users        []struct {
			Address                    string `json:"Address,omitempty"`
			Alias                      string `json:"Alias,omitempty"`
			BasicAuthenticationEnabled bool   `json:"BasicAuthenticationEnabled,omitempty"`
			Category                   string `json:"Category,omitempty"`
			City                       string `json:"City,omitempty"`
			ClearTextPassword          string `json:"ClearTextPassword,omitempty"`
			Company                    string `json:"Company,omitempty"`
			ConsoleAccess              bool   `json:"ConsoleAccess,omitempty"`
			Country                    string `json:"Country,omitempty"`
			CurrentSessions            []struct {
				ConnectionType  string `json:"ConnectionType,omitempty"`
				HostExclusive   bool   `json:"HostExclusive,omitempty"`
				InterfaceType   string `json:"InterfaceType,omitempty"`
				LastRequestDate string `json:"LastRequestDate,omitempty"`
				LocalAddress    string `json:"LocalAddress,omitempty"`
				LocalPort       int    `json:"LocalPort,omitempty"`
				LoginDate       string `json:"LoginDate,omitempty"`
				RemoteAddress   string `json:"RemoteAddress,omitempty"`
				RemotePort      int    `json:"RemotePort,omitempty"`
				RequestCount    int    `json:"RequestCount,omitempty"`
				Service         string `json:"Service,omitempty"`
				SessionID       int    `json:"SessionId,omitempty"`
				Status          string `json:"Status,omitempty"`
				Timeout         int    `json:"Timeout,omitempty"`
				UID             int    `json:"uid,omitempty"`
			} `json:"CurrentSessions,omitempty"`
			CurrentlyRemoteAccess bool   `json:"CurrentlyRemoteAccess,omitempty"`
			Email                 string `json:"Email,omitempty"`
			Enable                bool   `json:"Enable,omitempty"`
			FirstName             string `json:"FirstName,omitempty"`
			ForcePasswordChange   bool   `json:"ForcePasswordChange,omitempty"`
			Language              string `json:"Language,omitempty"`
			LastName              string `json:"LastName,omitempty"`
			LocalAccess           bool   `json:"LocalAccess,omitempty"`
			Login                 string `json:"Login,omitempty"`
			MaxSessionCount       int    `json:"MaxSessionCount,omitempty"`
			MobilePhoneNumber     string `json:"MobilePhoneNumber,omitempty"`
			OwnPass               bool   `json:"OwnPass,omitempty"`
			Password              string `json:"Password,omitempty"`
			PhoneNumbers          []any  `json:"PhoneNumbers,omitempty"`
			Role                  string `json:"Role,omitempty"`
			SecretAnswer          string `json:"SecretAnswer,omitempty"`
			SecretQuery           string `json:"SecretQuery,omitempty"`
			Zip                   string `json:"ZIP,omitempty"`
			UID                   int    `json:"uid,omitempty"`
		} `json:"Users,omitempty"`
		WANInterface string `json:"WANInterface,omitempty"`
	} `json:"UserAccounts,omitempty"`
	UserInterface struct {
		AutoUpdateServer   string `json:"AutoUpdateServer,omitempty"`
		AvailableLanguages string `json:"AvailableLanguages,omitempty"`
		BackgroundColor    string `json:"BackgroundColor,omitempty"`
		BackupDatas        []struct {
			Alias string `json:"Alias,omitempty"`
			Tag   string `json:"Tag,omitempty"`
			Value string `json:"Value,omitempty"`
			UID   int    `json:"uid,omitempty"`
		} `json:"BackupDatas,omitempty"`
		Brand           string `json:"Brand,omitempty"`
		ButtonColor     string `json:"ButtonColor,omitempty"`
		ButtonTextColor string `json:"ButtonTextColor,omitempty"`
		CurrentLanguage string `json:"CurrentLanguage,omitempty"`
		GuiLockTime     int    `json:"GuiLockTime,omitempty"`
		HideTables      []any  `json:"HideTables,omitempty"`
		Httpd           struct {
			HostAttackProtection bool   `json:"HostAttackProtection,omitempty"`
			MaxSessions          int    `json:"MaxSessions,omitempty"`
			Redirection          string `json:"Redirection,omitempty"`
			SessionTimeout       int    `json:"SessionTimeout,omitempty"`
		} `json:"Httpd,omitempty"`
		ISPHelpDesk   string `json:"ISPHelpDesk,omitempty"`
		ISPHelpPage   string `json:"ISPHelpPage,omitempty"`
		ISPHomePage   string `json:"ISPHomePage,omitempty"`
		ISPLogo       string `json:"ISPLogo,omitempty"`
		ISPLogoSize   int    `json:"ISPLogoSize,omitempty"`
		ISPMailServer string `json:"ISPMailServer,omitempty"`
		ISPName       string `json:"ISPName,omitempty"`
		ISPNewsServer string `json:"ISPNewsServer,omitempty"`
		LocalDisplay  struct {
			DisplayHeight int  `json:"DisplayHeight,omitempty"`
			DisplayWidth  int  `json:"DisplayWidth,omitempty"`
			GuiFlag       bool `json:"GuiFlag,omitempty"`
			Height        int  `json:"Height,omitempty"`
			Movable       bool `json:"Movable,omitempty"`
			PosX          int  `json:"PosX,omitempty"`
			PosY          int  `json:"PosY,omitempty"`
			Resizable     bool `json:"Resizable,omitempty"`
			Width         int  `json:"Width,omitempty"`
		} `json:"LocalDisplay,omitempty"`
		LoginRetryNumber       int    `json:"LoginRetryNumber,omitempty"`
		Market                 string `json:"Market,omitempty"`
		Password               string `json:"Password,omitempty"`
		PasswordMinLength      int    `json:"PasswordMinLength,omitempty"`
		PasswordRequired       bool   `json:"PasswordRequired,omitempty"`
		PasswordReset          bool   `json:"PasswordReset,omitempty"`
		PasswordUserSelectable bool   `json:"PasswordUserSelectable,omitempty"`
		RedirectionReason      string `json:"RedirectionReason,omitempty"`
		RemoteAccess           struct {
			Enable                       bool   `json:"Enable,omitempty"`
			GeneralCodeRemoteApplication string `json:"GeneralCodeRemoteApplication,omitempty"`
			Port                         int    `json:"Port,omitempty"`
			Protocol                     string `json:"Protocol,omitempty"`
			RemoteAccessHost             string `json:"RemoteAccessHost,omitempty"`
			RemoteApplicationEnable      bool   `json:"RemoteApplicationEnable,omitempty"`
			RemoteApplicationHTTPSPort   int    `json:"RemoteApplicationHTTPSPort,omitempty"`
			SupportedProtocols           string `json:"SupportedProtocols,omitempty"`
			Timeout                      int    `json:"Timeout,omitempty"`
		} `json:"RemoteAccess,omitempty"`
		RouterRedirectURL       string `json:"RouterRedirectURL,omitempty"`
		RouterRedirectURLEnable bool   `json:"RouterRedirectURLEnable,omitempty"`
		Screen                  struct {
			ClearOnOk    bool   `json:"ClearOnOk,omitempty"`
			DisplayState string `json:"DisplayState,omitempty"`
			DisplayTime  int    `json:"DisplayTime,omitempty"`
			Lines        []struct {
				TextToDisplay string `json:"TextToDisplay,omitempty"`
				UID           int    `json:"uid,omitempty"`
			} `json:"Lines,omitempty"`
			PixelLeap      int `json:"PixelLeap,omitempty"`
			Priority       int `json:"Priority,omitempty"`
			ScrollingSpeed int `json:"ScrollingSpeed,omitempty"`
		} `json:"Screen,omitempty"`
		TextColor        string `json:"TextColor,omitempty"`
		UpgradeAvailable bool   `json:"UpgradeAvailable,omitempty"`
		UserUpdateServer string `json:"UserUpdateServer,omitempty"`
		WarrantyDate     string `json:"WarrantyDate,omitempty"`
		BaseUrls         []any  `json:"baseUrls,omitempty"`
	} `json:"UserInterface,omitempty"`
	WebAccesses struct {
		PortTrigger    []any `json:"PortTrigger,omitempty"`
		WebRestriction []any `json:"WebRestriction,omitempty"`
	} `json:"WebAccesses,omitempty"`
	WiFi struct {
		AccessPoints []struct {
			ACs []struct {
				Acm                            bool   `json:"ACM,omitempty"`
				ACMSta                         bool   `json:"ACM_sta,omitempty"`
				Aifsn                          int    `json:"AIFSN,omitempty"`
				AIFSNSta                       int    `json:"AIFSN_sta,omitempty"`
				AccessCategory                 string `json:"AccessCategory,omitempty"`
				AckPolicy                      bool   `json:"AckPolicy,omitempty"`
				AckPolicySta                   bool   `json:"AckPolicy_sta,omitempty"`
				Alias                          string `json:"Alias,omitempty"`
				ECWMax                         int    `json:"ECWMax,omitempty"`
				ECWMaxSta                      int    `json:"ECWMax_sta,omitempty"`
				ECWMin                         int    `json:"ECWMin,omitempty"`
				ECWMinSta                      int    `json:"ECWMin_sta,omitempty"`
				OutQLenHistogramIntervals      string `json:"OutQLenHistogramIntervals,omitempty"`
				OutQLenHistogramSampleInterval int    `json:"OutQLenHistogramSampleInterval,omitempty"`
				Stats                          struct {
					BytesReceived          string `json:"BytesReceived,omitempty"`
					BytesSent              string `json:"BytesSent,omitempty"`
					DiscardPacketsReceived int    `json:"DiscardPacketsReceived,omitempty"`
					DiscardPacketsSent     int    `json:"DiscardPacketsSent,omitempty"`
					ErrorsReceived         int    `json:"ErrorsReceived,omitempty"`
					ErrorsSent             int    `json:"ErrorsSent,omitempty"`
					OutQLenHistogram       string `json:"OutQLenHistogram,omitempty"`
					PacketsReceived        string `json:"PacketsReceived,omitempty"`
					PacketsSent            string `json:"PacketsSent,omitempty"`
					RetransCount           int    `json:"RetransCount,omitempty"`
				} `json:"Stats,omitempty"`
				TxOpMax    int `json:"TxOpMax,omitempty"`
				TxOpMaxSta int `json:"TxOpMax_sta,omitempty"`
				UID        int `json:"uid,omitempty"`
			} `json:"ACs,omitempty"`
			Accounting struct {
				ClientPort            int    `json:"ClientPort,omitempty"`
				Enable                bool   `json:"Enable,omitempty"`
				InterimInterval       int    `json:"InterimInterval,omitempty"`
				Retries               int    `json:"Retries,omitempty"`
				RetryTimeout          int    `json:"RetryTimeout,omitempty"`
				SecondarySecret       string `json:"SecondarySecret,omitempty"`
				SecondaryServerIPAddr string `json:"SecondaryServerIPAddr,omitempty"`
				SecondaryServerPort   int    `json:"SecondaryServerPort,omitempty"`
				Secret                string `json:"Secret,omitempty"`
				ServerIPAddr          string `json:"ServerIPAddr,omitempty"`
				ServerPort            int    `json:"ServerPort,omitempty"`
			} `json:"Accounting,omitempty"`
			Alias             string `json:"Alias,omitempty"`
			AssociatedDevices []struct {
				Active                  bool   `json:"Active,omitempty"`
				AssociationCount        int    `json:"AssociationCount,omitempty"`
				AssociationTime         string `json:"AssociationTime,omitempty"`
				AssociationsDateTime    string `json:"AssociationsDateTime,omitempty"`
				AuthenticationCount     int    `json:"AuthenticationCount,omitempty"`
				AuthenticationState     bool   `json:"AuthenticationState,omitempty"`
				AuthenticationUsername  string `json:"AuthenticationUsername,omitempty"`
				DeauthenticationCount   int    `json:"DeauthenticationCount,omitempty"`
				DeviceType              string `json:"DeviceType,omitempty"`
				DisassociationCount     int    `json:"DisassociationCount,omitempty"`
				DisassociationsDateTime string `json:"DisassociationsDateTime,omitempty"`
				Encryption              string `json:"Encryption,omitempty"`
				IPAddress               string `json:"IPAddress,omitempty"`
				LastDataDownlinkRate    int    `json:"LastDataDownlinkRate,omitempty"`
				LastDataUplinkRate      int    `json:"LastDataUplinkRate,omitempty"`
				MACAddress              string `json:"MACAddress,omitempty"`
				MUSupport               bool   `json:"MUSupport,omitempty"`
				Noise                   int    `json:"Noise,omitempty"`
				OperatingStandard       string `json:"OperatingStandard,omitempty"`
				Retransmissions         int    `json:"Retransmissions,omitempty"`
				SecurityMode            string `json:"SecurityMode,omitempty"`
				SignalStrength          int    `json:"SignalStrength,omitempty"`
				Stats                   struct {
					AntennasRssi       string `json:"AntennasRssi,omitempty"`
					BytesReceived      string `json:"BytesReceived,omitempty"`
					BytesSent          string `json:"BytesSent,omitempty"`
					ErrorsReceived     string `json:"ErrorsReceived,omitempty"`
					ErrorsSent         int    `json:"ErrorsSent,omitempty"`
					FailedRetransCount int    `json:"FailedRetransCount,omitempty"`
					MultipleRetryCount int    `json:"MultipleRetryCount,omitempty"`
					PacketsReceived    string `json:"PacketsReceived,omitempty"`
					PacketsSent        string `json:"PacketsSent,omitempty"`
					RetransCount       int    `json:"RetransCount,omitempty"`
					RetryCount         int    `json:"RetryCount,omitempty"`
				} `json:"Stats,omitempty"`
				SupportedStandards string `json:"SupportedStandards,omitempty"`
				Uptime             int    `json:"Uptime,omitempty"`
				UID                int    `json:"uid,omitempty"`
			} `json:"AssociatedDevices,omitempty"`
			AssociationForbidden      bool   `json:"AssociationForbidden,omitempty"`
			AuthenticationServiceMode string `json:"AuthenticationServiceMode,omitempty"`
			BasicAuthenticationMode   string `json:"BasicAuthenticationMode,omitempty"`
			BasicDataTransmitRates    string `json:"BasicDataTransmitRates,omitempty"`
			Bridge                    string `json:"Bridge,omitempty"`
			DirectMulticast           bool   `json:"DirectMulticast,omitempty"`
			Enable                    bool   `json:"Enable,omitempty"`
			IP                        string `json:"Ip,omitempty"`
			IsolationEnable           bool   `json:"IsolationEnable,omitempty"`
			MACFiltering              struct {
				MACAddresses []any  `json:"MACAddresses,omitempty"`
				Mode         string `json:"Mode,omitempty"`
			} `json:"MACFiltering,omitempty"`
			MaxAssociatedDevices         int    `json:"MaxAssociatedDevices,omitempty"`
			OperationalDataTransmitRates string `json:"OperationalDataTransmitRates,omitempty"`
			PossibleDataTransmitRates    string `json:"PossibleDataTransmitRates,omitempty"`
			ProxyMode                    string `json:"ProxyMode,omitempty"`
			RadioMeasurements            struct {
				BeaconRequestActive  bool `json:"BeaconRequestActive,omitempty"`
				BeaconRequestPassive bool `json:"BeaconRequestPassive,omitempty"`
				BeaconRequestTable   bool `json:"BeaconRequestTable,omitempty"`
				LinkMeasurement      bool `json:"LinkMeasurement,omitempty"`
				NeighborReport       bool `json:"NeighborReport,omitempty"`
			} `json:"RadioMeasurements,omitempty"`
			RetryLimit               int    `json:"RetryLimit,omitempty"`
			SSIDAdvertisementEnabled bool   `json:"SSIDAdvertisementEnabled,omitempty"`
			SSIDReference            string `json:"SSIDReference,omitempty"`
			Security                 struct {
				AntiCloggingThreshold       int    `json:"AntiCloggingThreshold,omitempty"`
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
				RadiusServerPort            int    `json:"RadiusServerPort,omitempty"`
				RekeyingInterval            int    `json:"RekeyingInterval,omitempty"`
				Reset                       bool   `json:"Reset,omitempty"`
				SAEPassphrase               string `json:"SAEPassphrase,omitempty"`
				SecondaryRadiusSecret       string `json:"SecondaryRadiusSecret,omitempty"`
				SecondaryRadiusServerIPAddr string `json:"SecondaryRadiusServerIPAddr,omitempty"`
				SecondaryRadiusServerPort   int    `json:"SecondaryRadiusServerPort,omitempty"`
			} `json:"Security,omitempty"`
			Status                string `json:"Status,omitempty"`
			UAPSDCapability       bool   `json:"UAPSDCapability,omitempty"`
			UAPSDEnable           bool   `json:"UAPSDEnable,omitempty"`
			VirtualInterfaceIndex int    `json:"VirtualInterfaceIndex,omitempty"`
			WMMCapability         bool   `json:"WMMCapability,omitempty"`
			WMMEnable             bool   `json:"WMMEnable,omitempty"`
			Wps                   struct {
				ConfigMethodsEnabled   string `json:"ConfigMethodsEnabled,omitempty"`
				ConfigMethodsSupported string `json:"ConfigMethodsSupported,omitempty"`
				DevicePIN              string `json:"DevicePIN,omitempty"`
				Enable                 bool   `json:"Enable,omitempty"`
				EnrolleePIN            string `json:"EnrolleePIN,omitempty"`
				M1AccessControlList    string `json:"M1AccessControlList,omitempty"`
				M1AccessControlRule    string `json:"M1AccessControlRule,omitempty"`
				SecurityModesEnabled   string `json:"SecurityModesEnabled,omitempty"`
				SessionStatus          string `json:"SessionStatus,omitempty"`
				Timeout                int    `json:"Timeout,omitempty"`
				Unconfigured           bool   `json:"Unconfigured,omitempty"`
			} `json:"WPS,omitempty"`
			ZeroPacketLost int `json:"ZeroPacketLost,omitempty"`
			UID            int `json:"uid,omitempty"`
		} `json:"AccessPoints,omitempty"`
		BandSteering struct {
			BsdParameters struct {
				AirtimeSlowestLink int  `json:"AirtimeSlowestLink,omitempty"`
				BSSTransition      bool `json:"BSSTransition,omitempty"`
				BounceDetection    struct {
					Counts     int `json:"Counts,omitempty"`
					DwellTime  int `json:"DwellTime,omitempty"`
					WindowTime int `json:"WindowTime,omitempty"`
				} `json:"BounceDetection,omitempty"`
				BsdScheme          int  `json:"BsdScheme,omitempty"`
				LegacyBandSteering bool `json:"LegacyBandSteering,omitempty"`
				MessageLevelDebug  bool `json:"MessageLevelDebug,omitempty"`
				PhyRate            int  `json:"PhyRate,omitempty"`
			} `json:"BsdParameters,omitempty"`
			Devices    []any  `json:"Devices,omitempty"`
			Enable     bool   `json:"Enable,omitempty"`
			Interfaces []any  `json:"Interfaces,omitempty"`
			Status     string `json:"Status,omitempty"`
		} `json:"BandSteering,omitempty"`
		Broadcom struct {
			CrashNumberSinceBoot     int    `json:"CrashNumberSinceBoot,omitempty"`
			DetectedCrash            string `json:"DetectedCrash,omitempty"`
			DongleMemDumpLocalPath   string `json:"DongleMemDumpLocalPath,omitempty"`
			DriverErrorManagement    string `json:"DriverErrorManagement,omitempty"`
			LastCrashSinceBoot       string `json:"LastCrashSinceBoot,omitempty"`
			LastCrashSinceReset      string `json:"LastCrashSinceReset,omitempty"`
			ReloadNumberBeforeReboot int    `json:"ReloadNumberBeforeReboot,omitempty"`
		} `json:"Broadcom,omitempty"`
		NeighboringWiFiDiagnostic struct {
			DiagnosticsState string `json:"DiagnosticsState,omitempty"`
			Result           []any  `json:"Result,omitempty"`
		} `json:"NeighboringWiFiDiagnostic,omitempty"`
		Radios          []Radio `json:"Radios,omitempty"`
		SSIDs           []SSID  `json:"SSIDs,omitempty"`
		VisionEnable    bool    `json:"VisionEnable,omitempty"`
		VisionInterface string  `json:"VisionInterface,omitempty"`
		Wms             struct {
			BeaconReportPeriod int   `json:"BeaconReportPeriod,omitempty"`
			Enable             bool  `json:"Enable,omitempty"`
			HeaderLogPeriod    int   `json:"HeaderLogPeriod,omitempty"`
			Period             int   `json:"Period,omitempty"`
			BeaconAPs          []any `json:"beaconAPs,omitempty"`
		} `json:"WMS,omitempty"`
	} `json:"WiFi,omitempty"`
}

type Radio struct {
	Ampdu                    int    `json:"AMPDU,omitempty"`
	Ampdumpdu                int    `json:"AMPDUMPDU,omitempty"`
	Amsdu                    int    `json:"AMSDU,omitempty"`
	ATFEnable                bool   `json:"ATFEnable,omitempty"`
	AdminStatus              bool   `json:"AdminStatus,omitempty"`
	Alias                    string `json:"Alias,omitempty"`
	AutoChannelAcsTriggerVar int    `json:"AutoChannelAcsTriggerVar,omitempty"`
	AutoChannelEnable        bool   `json:"AutoChannelEnable,omitempty"`
	AutoChannelList          string `json:"AutoChannelList,omitempty"`
	AutoChannelLockoutPeriod int    `json:"AutoChannelLockoutPeriod,omitempty"`
	AutoChannelMaxAcs        int    `json:"AutoChannelMaxAcs,omitempty"`
	AutoChannelRefreshPeriod int    `json:"AutoChannelRefreshPeriod,omitempty"`
	AutoChannelSupported     bool   `json:"AutoChannelSupported,omitempty"`
	AutoChannelTrigger       bool   `json:"AutoChannelTrigger,omitempty"`
	BasicDataTransmitRates   string `json:"BasicDataTransmitRates,omitempty"`
	BeaconPeriod             int    `json:"BeaconPeriod,omitempty"`
	BlackListedChannels      string `json:"BlackListedChannels,omitempty"`
	BoardSpecificChipIndex   int    `json:"BoardSpecificChipIndex,omitempty"`
	BurstModeEnable          bool   `json:"BurstModeEnable,omitempty"`
	CCAReport                string `json:"CCAReport,omitempty"`
	CCARequest               string `json:"CCARequest,omitempty"`
	CSACount                 int    `json:"CSACount,omitempty"`
	CSADeauth                string `json:"CSADeauth,omitempty"`
	CSAEnable                bool   `json:"CSAEnable,omitempty"`
	Channel                  int    `json:"Channel,omitempty"`
	ChannelHoppingEnable     bool   `json:"ChannelHoppingEnable,omitempty"`
	ChannelHoppingHistory    struct {
		Channels  string `json:"Channels,omitempty"`
		Count     int    `json:"Count,omitempty"`
		Reason    string `json:"Reason,omitempty"`
		Timestamp string `json:"Timestamp,omitempty"`
	} `json:"ChannelHoppingHistory,omitempty"`
	ChannelHoppingStatus             bool   `json:"ChannelHoppingStatus,omitempty"`
	ChannelsInUse                    string `json:"ChannelsInUse,omitempty"`
	CurrentOperatingChannelBandwidth int64
	DFSChannel                       string `json:"DFSChannel,omitempty"`
	DLMUMIMOEnabled                  bool   `json:"DLMUMIMOEnabled,omitempty"`
	DTIMPeriod                       int    `json:"DTIMPeriod,omitempty"`
	DeviceOperationMode              string `json:"DeviceOperationMode,omitempty"`
	Diversity11B                     bool   `json:"Diversity11b,omitempty"`
	DownlinkOFDMAEnable              bool   `json:"DownlinkOFDMAEnable,omitempty"`
	Enable                           bool   `json:"Enable,omitempty"`
	Enable11Ac2G                     bool   `json:"Enable11ac2G,omitempty"`
	ExtensionChannel                 string `json:"ExtensionChannel,omitempty"`
	FragmentationThreshold           int    `json:"FragmentationThreshold,omitempty"`
	FrameBurstEnabled                bool   `json:"FrameBurstEnabled,omitempty"`
	GreenAPDelay                     int    `json:"GreenAPDelay,omitempty"`
	GreenAPEnabled                   bool   `json:"GreenAPEnabled,omitempty"`
	GuardInterval                    string `json:"GuardInterval,omitempty"`
	HostBasedScbEnable               bool   `json:"HostBasedScbEnable,omitempty"`
	HybridScanMode                   bool   `json:"HybridScanMode,omitempty"`
	IEEE80211HEnabled                bool   `json:"IEEE80211hEnabled,omitempty"`
	IEEE80211HSupported              bool   `json:"IEEE80211hSupported,omitempty"`
	IfcName                          string `json:"IfcName,omitempty"`
	IncreasedPowerEnable             bool   `json:"IncreasedPowerEnable,omitempty"`
	InitiateACS                      string `json:"InitiateACS,omitempty"`
	Interference                     string `json:"Interference,omitempty"`
	LastChange                       int    `json:"LastChange,omitempty"`
	LastStatsReset                   int    `json:"LastStatsReset,omitempty"`
	LocationDescription              string `json:"LocationDescription,omitempty"`
	LongRetryLimit                   int    `json:"LongRetryLimit,omitempty"`
	LowerLayers                      string `json:"LowerLayers,omitempty"`
	Mcs                              int    `json:"MCS,omitempty"`
	MaxBitRate                       int64  `json:"MaxBitRate,omitempty"`
	Name                             string `json:"Name,omitempty"`
	NewChannelsEnable                bool   `json:"NewChannelsEnable,omitempty"`
	OperatingChannelBandwidth        string `json:"OperatingChannelBandwidth,omitempty"`
	OperatingFrequencyBand           string `json:"OperatingFrequencyBand,omitempty"`
	OperatingMCSSet                  string `json:"OperatingMCSSet,omitempty"`
	OperatingStandards               string `json:"OperatingStandards,omitempty"`
	OperationalDataTransmitRates     string `json:"OperationalDataTransmitRates,omitempty"`
	PacketAggregationEnable          bool   `json:"PacketAggregationEnable,omitempty"`
	PossibleChannels                 string `json:"PossibleChannels,omitempty"`
	PreambleType                     string `json:"PreambleType,omitempty"`
	RPIHistogramReport               string `json:"RPIHistogramReport,omitempty"`
	RPIHistogramRequest              string `json:"RPIHistogramRequest,omitempty"`
	RTSThreshold                     int    `json:"RTSThreshold,omitempty"`
	RadarDetections                  int    `json:"RadarDetections,omitempty"`
	RegulatoryDomain                 string `json:"RegulatoryDomain,omitempty"`
	RegulatoryRegionSubRegion        string `json:"RegulatoryRegionSubRegion,omitempty"`
	ResetStats                       bool   `json:"ResetStats,omitempty"`
	RetryLimit                       int    `json:"RetryLimit,omitempty"`
	RxSTBC                           string `json:"RxSTBC,omitempty"`
	SingleTxCCK                      bool   `json:"SingleTxCCK,omitempty"`
	SiteSurvey                       struct {
		ChannelSurveys []any  `json:"ChannelSurveys,omitempty"`
		ChannelsToTest string `json:"ChannelsToTest,omitempty"`
		MaxDwellTime   int    `json:"MaxDwellTime,omitempty"`
		MinDwellTime   int    `json:"MinDwellTime,omitempty"`
		NbEntries      int    `json:"NbEntries,omitempty"`
		SamplePeriod   int    `json:"SamplePeriod,omitempty"`
		ScanMode       string `json:"ScanMode,omitempty"`
		State          string `json:"State,omitempty"`
	} `json:"SiteSurvey,omitempty"`
	SplittedOperatingFrequencyBand string `json:"SplittedOperatingFrequencyBand,omitempty"`
	Stats                          struct {
		Active                 string `json:"Active,omitempty"`
		BKCount                string `json:"BK_count,omitempty"`
		BcnCount               string `json:"Bcn_count,omitempty"`
		BeCount                string `json:"Be_count,omitempty"`
		BytesReceived          string `json:"BytesReceived,omitempty"`
		BytesSent              string `json:"BytesSent,omitempty"`
		CabCount               string `json:"Cab_count,omitempty"`
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
		PacketsReceived        string `json:"PacketsReceived,omitempty"`
		PacketsSent            string `json:"PacketsSent,omitempty"`
		SampleCount            int    `json:"SampleCount,omitempty"`
		ViCount                string `json:"Vi_count,omitempty"`
		VoCount                string `json:"Vo_count,omitempty"`
	} `json:"Stats,omitempty"`
	Status                     string `json:"Status,omitempty"`
	StoppedBy                  string `json:"StoppedBy,omitempty"`
	SupportedChannelBandwidth  string `json:"SupportedChannelBandwidth,omitempty"`
	SupportedDataTransmitRates string `json:"SupportedDataTransmitRates,omitempty"`
	SupportedFrequencyBands    string `json:"SupportedFrequencyBands,omitempty"`
	SupportedStandards         string `json:"SupportedStandards,omitempty"`
	TransmitBeamForming        bool   `json:"TransmitBeamForming,omitempty"`
	TransmitPower              float64
	TransmitPowerMax           float64 `json:"TransmitPowerMax,omitempty"`
	TransmitPowerSupported     string  `json:"TransmitPowerSupported,omitempty"`
	TxLDPC                     string  `json:"TxLDPC,omitempty"`
	TxSTBC                     string  `json:"TxSTBC,omitempty"`
	UplinkOFDMAEnable          bool    `json:"UplinkOFDMAEnable,omitempty"`
	Upstream                   bool    `json:"Upstream,omitempty"`
	VoWEnable                  bool    `json:"VoWEnable,omitempty"`
	WirelessScan               struct {
		ChannelsToTest string `json:"ChannelsToTest,omitempty"`
		SSIDs          []any  `json:"SSIDs,omitempty"`
		State          string `json:"State,omitempty"`
	} `json:"WirelessScan,omitempty"`
	GModeProtectionEnabled bool `json:"gModeProtectionEnabled,omitempty"`
	UID                    int  `json:"uid,omitempty"`
}

func (r *Radio) UnmarshalJSON(data []byte) error {
	type alias Radio
	aux := &struct {
		CurrentOperatingChannelBandwidth string `json:"CurrentOperatingChannelBandwidth"`
		TransmitPower                    int    `json:"TransmitPower"`
		*alias
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
	Alias          string `json:"Alias,omitempty"`
	Bssid          string `json:"BSSID,omitempty"`
	Enable         bool   `json:"Enable,omitempty"`
	IfcName        string `json:"IfcName,omitempty"`
	LastChange     int    `json:"LastChange,omitempty"`
	LastStatsReset int    `json:"LastStatsReset,omitempty"`
	LowerLayers    string `json:"LowerLayers,omitempty"`
	MACAddress     string `json:"MACAddress,omitempty"`
	Name           string `json:"Name,omitempty"`
	ResetStats     bool   `json:"ResetStats,omitempty"`
	SSID           string `json:"SSID,omitempty"`
	Stats          struct {
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
	Status    string `json:"Status,omitempty"`
	StoppedBy string `json:"StoppedBy,omitempty"`
	UID       int    `json:"uid,omitempty"`
}

// ValueResponse represents the full response from the router from the getValue
// method
type ValueResponse struct {
	Device Device `json:"Device,omitempty"`
}

type DeviceInfo struct {
	APIVersion                string       `json:"APIVersion,omitempty"`
	AdditionalHardwareVersion string       `json:"AdditionalHardwareVersion,omitempty"`
	AdditionalSoftwareVersion string       `json:"AdditionalSoftwareVersion,omitempty"`
	BackupSoftwareVersion     string       `json:"BackupSoftwareVersion,omitempty"`
	BackupTimeStamp           time.Time    `json:"BackupTimeStamp,omitempty"`
	BootloaderVersion         string       `json:"BootloaderVersion,omitempty"`
	BuildDate                 time.Time    `json:"BuildDate,omitempty"`
	Clid                      string       `json:"CLID,omitempty"`
	ConfigBackupRestoreEnable bool         `json:"ConfigBackupRestoreEnable,omitempty"`
	Country                   string       `json:"Country,omitempty"`
	CrashHistory              CrashHistory `json:"CrashHistory,omitempty"`
	CustomerModelName         string       `json:"CustomerModelName,omitempty"`
	Description               string       `json:"Description,omitempty"`
	DeviceCategory            string       `json:"DeviceCategory,omitempty"`
	DeviceLog                 string       `json:"DeviceLog,omitempty"`
	EventLog                  string       `json:"EventLog,omitempty"`
	ExternalFirmwareVersion   string       `json:"ExternalFirmwareVersion,omitempty"`
	FirstConnection           bool         `json:"FirstConnection,omitempty"`
	FirstUseDate              time.Time    `json:"FirstUseDate,omitempty"`
	FlashMemoryStatus         struct {
		Free  int `json:"Free,omitempty"`
		Total int `json:"Total,omitempty"`
	} `json:"FlashMemoryStatus,omitempty"`
	FlushDeviceLog          bool   `json:"FlushDeviceLog,omitempty"`
	GUIAPIVersion           string `json:"GUIAPIVersion,omitempty"`
	GUIFirmwareVersion      string `json:"GUIFirmwareVersion,omitempty"`
	HardwareVersion         string `json:"HardwareVersion,omitempty"`
	InternalFirmwareVersion string `json:"InternalFirmwareVersion,omitempty"`
	Locations               []any  `json:"Locations,omitempty"`
	Logging                 struct {
		LogLevel     string `json:"LogLevel,omitempty"`
		ResetLogOper bool   `json:"ResetLogOper,omitempty"`
		Syslog       struct {
			Destinations []struct {
				Alias               string `json:"Alias,omitempty"`
				Enable              bool   `json:"Enable,omitempty"`
				FileStorageLocation string `json:"FileStorageLocation,omitempty"`
				LogSize             int    `json:"LogSize,omitempty"`
				LoggerCategories    string `json:"LoggerCategories,omitempty"`
				SourceIndex         int    `json:"SourceIndex,omitempty"`
				Status              string `json:"Status,omitempty"`
				SyslogConfig        string `json:"SyslogConfig,omitempty"`
				UID                 int    `json:"uid,omitempty"`
			} `json:"Destinations,omitempty"`
			DisplayKernelLogs   bool   `json:"DisplayKernelLogs,omitempty"`
			Enable              bool   `json:"Enable,omitempty"`
			FileStorageLocation string `json:"FileStorageLocation,omitempty"`
			LogStorage          string `json:"LogStorage,omitempty"`
			Sources             []struct {
				Alias              string `json:"Alias,omitempty"`
				Enable             bool   `json:"Enable,omitempty"`
				FileSourceLocation string `json:"FileSourceLocation,omitempty"`
				InternalSource     bool   `json:"InternalSource,omitempty"`
				KernelSource       bool   `json:"KernelSource,omitempty"`
				Network            struct {
					Enable   bool   `json:"Enable,omitempty"`
					Port     int    `json:"Port,omitempty"`
					Protocol string `json:"Protocol,omitempty"`
				} `json:"Network,omitempty"`
				UnixStream bool `json:"UnixStream,omitempty"`
				UID        int  `json:"uid,omitempty"`
			} `json:"Sources,omitempty"`
		} `json:"Syslog,omitempty"`
	} `json:"Logging,omitempty"`
	MACAddress      string `json:"MACAddress,omitempty"`
	Manufacturer    string `json:"Manufacturer,omitempty"`
	ManufacturerOUI string `json:"ManufacturerOUI,omitempty"`
	MemoryStatus    struct {
		Free  int `json:"Free,omitempty"`
		Total int `json:"Total,omitempty"`
	} `json:"MemoryStatus,omitempty"`
	Mode              string `json:"Mode,omitempty"`
	ModelName         string `json:"ModelName,omitempty"`
	ModelNumber       string `json:"ModelNumber,omitempty"`
	NetworkProperties struct {
		MaxTCPWindowSize  int    `json:"MaxTCPWindowSize,omitempty"`
		TCPImplementation string `json:"TCPImplementation,omitempty"`
	} `json:"NetworkProperties,omitempty"`
	NodesToRestore  string `json:"NodesToRestore,omitempty"`
	ONTSerialNumber string `json:"ONTSerialNumber,omitempty"`
	Processors      []struct {
		Alias        string `json:"Alias,omitempty"`
		Architecture string `json:"Architecture,omitempty"`
		UID          int    `json:"uid,omitempty"`
	} `json:"Processors,omitempty"`
	ProductClass     string `json:"ProductClass,omitempty"`
	ProvisioningCode string `json:"ProvisioningCode,omitempty"`
	ProxierInfo      struct {
		ManufacturerOUI string `json:"ManufacturerOUI,omitempty"`
		ProductClass    string `json:"ProductClass,omitempty"`
		ProxyProtocol   string `json:"ProxyProtocol,omitempty"`
		SerialNumber    string `json:"SerialNumber,omitempty"`
	} `json:"ProxierInfo,omitempty"`
	RebootCount  int    `json:"RebootCount,omitempty"`
	RebootStatus int    `json:"RebootStatus,omitempty"`
	ResetStatus  int    `json:"ResetStatus,omitempty"`
	RouterName   string `json:"RouterName,omitempty"`
	SNMP         bool   `json:"SNMP,omitempty"`
	SimpleLogs   struct {
		CallLog     string `json:"CallLog,omitempty"`
		FirewallLog string `json:"FirewallLog,omitempty"`
		SystemLog   string `json:"SystemLog,omitempty"`
	} `json:"SimpleLogs,omitempty"`
	SoftwareVersion   string `json:"SoftwareVersion,omitempty"`
	SpecVersion       string `json:"SpecVersion,omitempty"`
	TemperatureStatus struct {
		TemperatureSensors []struct {
			Alias           string `json:"Alias,omitempty"`
			Enable          bool   `json:"Enable,omitempty"`
			HighAlarmTime   string `json:"HighAlarmTime,omitempty"`
			HighAlarmValue  int    `json:"HighAlarmValue,omitempty"`
			LastUpdate      string `json:"LastUpdate,omitempty"`
			LowAlarmTime    string `json:"LowAlarmTime,omitempty"`
			LowAlarmValue   int    `json:"LowAlarmValue,omitempty"`
			MaxTime         string `json:"MaxTime,omitempty"`
			MaxValue        int    `json:"MaxValue,omitempty"`
			MinTime         string `json:"MinTime,omitempty"`
			MinValue        int    `json:"MinValue,omitempty"`
			Name            string `json:"Name,omitempty"`
			PollingInterval int    `json:"PollingInterval,omitempty"`
			Reset           bool   `json:"Reset,omitempty"`
			ResetTime       string `json:"ResetTime,omitempty"`
			Status          string `json:"Status,omitempty"`
			Value           int    `json:"Value,omitempty"`
			UID             int    `json:"uid,omitempty"`
		} `json:"TemperatureSensors,omitempty"`
	} `json:"TemperatureStatus,omitempty"`
	UpTime            int   `json:"UpTime,omitempty"`
	UpdateStatus      int   `json:"UpdateStatus,omitempty"`
	UserConfigFiles   []any `json:"UserConfigFiles,omitempty"`
	VendorConfigFiles []struct {
		Alias               string `json:"Alias,omitempty"`
		Date                string `json:"Date,omitempty"`
		Description         string `json:"Description,omitempty"`
		Name                string `json:"Name,omitempty"`
		UseForBackupRestore bool   `json:"UseForBackupRestore,omitempty"`
		Version             string `json:"Version,omitempty"`
		UID                 int    `json:"uid,omitempty"`
	} `json:"VendorConfigFiles,omitempty"`
	VendorLogFiles []struct {
		Alias           string `json:"Alias,omitempty"`
		DiagnosticState string `json:"DiagnosticState,omitempty"`
		LogData         string `json:"LogData,omitempty"`
		MaximumSize     int    `json:"MaximumSize,omitempty"`
		Name            string `json:"Name,omitempty"`
		Persistent      bool   `json:"Persistent,omitempty"`
		UID             int    `json:"uid,omitempty"`
	} `json:"VendorLogFiles,omitempty"`
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
		BackupTimeStamp string  `json:"BackupTimeStamp,omitempty"`
		BuildDate       string  `json:"BuildDate,omitempty"`
		FirstUseDate    string  `json:"FirstUseDate,omitempty"`
		RebootStatus    float64 `json:"RebootStatus,omitempty"`
		ResetStatus     float64 `json:"ResetStatus,omitempty"`
		UpdateStatus    float64 `json:"UpdateStatus,omitempty"`
		*alias
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

	switch aux.ModelName {
	case "2864":
		d.ModelName = "Connection Hub"
	case "4350":
		d.ModelName = "Home Hub 1000"
	case "5250":
		d.ModelName = "Home Hub 2000"
	case "5566":
		d.ModelName = "Home Hub 3000"
	case "5689":
		d.ModelName = "Home Hub 4000"
	case "5690":
		d.ModelName = "Giga Hub"
	default:
		slog.Warn("unknown model name", "model_name", aux.ModelName)
		d.ModelName = aux.ModelName
	}

	return nil
}

type CrashHistory struct {
	LastCrashDate        time.Time `json:"LastCrashDate,omitempty"`
	MonthlyNumberOfCrash int       `json:"MonthlyNumberOfCrash,omitempty"`
	NumberOfCrash        int       `json:"NumberOfCrash,omitempty"`
}

func (c *CrashHistory) UnmarshalJSON(b []byte) error {
	type alias CrashHistory
	aux := struct {
		LastCrashDate string `json:"LastCrashDate,omitempty"`
		*alias
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
	AccessPoint           string `json:"AccessPoint,omitempty"`
	Active                bool   `json:"Active,omitempty"`
	ActiveLastChange      string `json:"ActiveLastChange,omitempty"`
	AddressSource         string `json:"AddressSource,omitempty"`
	Alias                 string `json:"Alias,omitempty"`
	AssociatedDevice      string `json:"AssociatedDevice,omitempty"`
	BlacklistStatus       bool   `json:"BlacklistStatus,omitempty"`
	ClientID              string `json:"ClientID,omitempty"`
	DHCPClient            string `json:"DHCPClient,omitempty"`
	DetectedDeviceType    string `json:"DetectedDeviceType,omitempty"`
	DeviceTypeAssociation string `json:"DeviceTypeAssociation,omitempty"`
	Hidden                bool   `json:"Hidden,omitempty"`
	History               struct {
		AddressSource   string `json:"AddressSource,omitempty"`
		ClientID        string `json:"ClientID,omitempty"`
		HostName        string `json:"HostName,omitempty"`
		IPAddress       string `json:"IPAddress,omitempty"`
		IPv6Address     string `json:"IPv6Address,omitempty"`
		Layer1Interface string `json:"Layer1Interface,omitempty"`
		Layer3Interface string `json:"Layer3Interface,omitempty"`
		Options         []struct {
			OptionTag   int    `json:"OptionTag,omitempty"`
			OptionValue string `json:"OptionValue,omitempty"`
			UID         int    `json:"uid,omitempty"`
		} `json:"Options,omitempty"`
		UserClassID     string `json:"UserClassID,omitempty"`
		VendorClassID   string `json:"VendorClassID,omitempty"`
		VendorClassIDv6 string `json:"VendorClassIDv6,omitempty"`
	} `json:"History,omitempty"`
	HostName      string `json:"HostName,omitempty"`
	IPAddress     string `json:"IPAddress,omitempty"`
	IPv4Addresses []struct {
		Active    bool   `json:"Active,omitempty"`
		IPAddress string `json:"IPAddress,omitempty"`
		UID       int    `json:"uid,omitempty"`
	} `json:"IPv4Addresses,omitempty"`
	IPv6Addresses      []json.RawMessage `json:"IPv6Addresses,omitempty"`
	Icon               string            `json:"Icon,omitempty"`
	InterfaceType      string            `json:"InterfaceType,omitempty"`
	Layer1Interface    string            `json:"Layer1Interface,omitempty"`
	Layer3Interface    string            `json:"Layer3Interface,omitempty"`
	LeaseDuration      int               `json:"LeaseDuration,omitempty"`
	LeaseStart         int               `json:"LeaseStart,omitempty"`
	LeaseTimeRemaining int               `json:"LeaseTimeRemaining,omitempty"`
	Options            []json.RawMessage `json:"Options,omitempty"`
	PhysAddress        string            `json:"PhysAddress,omitempty"`
	SysfsID            string            `json:"SysfsId,omitempty"`
	UnblockHoursCount  int               `json:"UnblockHoursCount,omitempty"`
	UserClassID        string            `json:"UserClassID,omitempty"`
	UserDeviceType     string            `json:"UserDeviceType,omitempty"`
	UserFriendlyName   string            `json:"UserFriendlyName,omitempty"`
	UserHostName       string            `json:"UserHostName,omitempty"`
	VendorClassID      string            `json:"VendorClassID,omitempty"`
	VendorClassIDv6    string            `json:"VendorClassIDv6,omitempty"`
	UID                int               `json:"uid,omitempty"`
}

type EthernetInterface struct {
	Alias             string               `json:"Alias,omitempty"`
	AssociatedDevices []any                `json:"AssociatedDevices,omitempty"`
	CurrentBitRate    int64                `json:"CurrentBitRate,omitempty"`
	Diagnostics       InterfaceDiagnostics `json:"Diagnostics,omitempty"`
	DuplexMode        string               `json:"DuplexMode,omitempty"`
	EEECapability     bool                 `json:"EEECapability,omitempty"`
	EEEEnable         bool                 `json:"EEEEnable,omitempty"`
	Enable            bool                 `json:"Enable,omitempty"`
	IfcName           string               `json:"IfcName,omitempty"`
	LastChange        int                  `json:"LastChange,omitempty"`
	LastStatsReset    int                  `json:"LastStatsReset,omitempty"`
	LowerLayers       string               `json:"LowerLayers,omitempty"`
	MACAddress        string               `json:"MACAddress,omitempty"`
	MTUSize           int                  `json:"MTUSize,omitempty"`
	MaxBitRate        int                  `json:"MaxBitRate,omitempty"`
	Name              string               `json:"Name,omitempty"`
	PhyNum            int                  `json:"PhyNum,omitempty"`
	ResetStats        bool                 `json:"ResetStats,omitempty"`
	Role              string               `json:"Role,omitempty"`
	Stats             InterfaceStats       `json:"Stats,omitempty"`
	Status            string               `json:"Status,omitempty"`
	StoppedBy         string               `json:"StoppedBy,omitempty"`
	Upstream          bool                 `json:"Upstream,omitempty"`
	UID               int                  `json:"uid,omitempty"`
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

type InterfaceDiagnostics struct {
	CableLength       int    `json:"CableLength,omitempty"`
	CableStatus       string `json:"CableStatus,omitempty"`
	CurrentDuplexMode string `json:"CurrentDuplexMode,omitempty"`
}

type OpticalInterface struct {
	Alarm       string `json:"Alarm,omitempty"`
	Alias       string `json:"Alias,omitempty"`
	BIASCurrent int64  `json:"BIASCurrent,omitempty"`
	CATV        struct {
		Alarm            string `json:"Alarm,omitempty"`
		RfRxOpticalPower int    `json:"RfRxOpticalPower,omitempty"`
		RfVoltage        int    `json:"RfVoltage,omitempty"`
		Status           string `json:"Status,omitempty"`
	} `json:"CATV,omitempty"`
	Enable                      bool   `json:"Enable,omitempty"`
	IfcName                     string `json:"IfcName,omitempty"`
	LastChange                  int64  `json:"LastChange,omitempty"`
	LastStatsReset              int    `json:"LastStatsReset,omitempty"`
	LowerLayers                 string `json:"LowerLayers,omitempty"`
	LowerOpticalThreshold       int64  `json:"LowerOpticalThreshold,omitempty"`
	LowerTransmitPowerThreshold int64  `json:"LowerTransmitPowerThreshold,omitempty"`
	Name                        string `json:"Name,omitempty"`
	OpticalPartNumber           string `json:"OpticalPartNumber,omitempty"`
	OpticalSignalLevel          int64  `json:"OpticalSignalLevel,omitempty"`
	OpticalVendorName           string `json:"OpticalVendorName,omitempty"`
	PonStats                    struct {
		GemPorts []struct {
			BytesReceived            string `json:"BytesReceived,omitempty"`
			BytesSent                string `json:"BytesSent,omitempty"`
			Direction                string `json:"Direction,omitempty"`
			DiscardedPacketsReceived int    `json:"DiscardedPacketsReceived,omitempty"`
			DiscardedPacketsSent     int    `json:"DiscardedPacketsSent,omitempty"`
			FlowType                 string `json:"FlowType,omitempty"`
			ID                       int    `json:"Id,omitempty"`
			Index                    int    `json:"Index,omitempty"`
			PacketsReceived          int    `json:"PacketsReceived,omitempty"`
			PacketsSent              int    `json:"PacketsSent,omitempty"`
			TcontIndex               int    `json:"TcontIndex,omitempty"`
			UID                      int    `json:"uid,omitempty"`
		} `json:"GemPorts,omitempty"`
		Reset  bool `json:"Reset,omitempty"`
		Tconts []struct {
			AllocID        int `json:"AllocId,omitempty"`
			GemPacketsSent int `json:"GemPacketsSent,omitempty"`
			Index          int `json:"Index,omitempty"`
			UID            int `json:"uid,omitempty"`
		} `json:"Tconts,omitempty"`
	} `json:"PonStats,omitempty"`
	ResetStats bool `json:"ResetStats,omitempty"`
	RogueOnu   struct {
		RogueOnuCount           int    `json:"RogueOnuCount,omitempty"`
		RogueOnuDetectionEnable bool   `json:"RogueOnuDetectionEnable,omitempty"`
		RogueOnuOccurrences     []any  `json:"RogueOnuOccurrences,omitempty"`
		RogueOnuStatus          string `json:"RogueOnuStatus,omitempty"`
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
	Status        string `json:"Status,omitempty"`
	StoppedBy     string `json:"StoppedBy,omitempty"`
	SupportedSFPs []struct {
		PartNumber string `json:"PartNumber,omitempty"`
		Type       string `json:"Type,omitempty"`
		VendorName string `json:"VendorName,omitempty"`
		UID        int    `json:"uid,omitempty"`
	} `json:"SupportedSFPs,omitempty"`
	Temperature                 int64 `json:"Temperature,omitempty"`
	TransmitOpticalLevel        int64 `json:"TransmitOpticalLevel,omitempty"`
	UpperOpticalThreshold       int64 `json:"UpperOpticalThreshold,omitempty"`
	UpperTransmitPowerThreshold int64 `json:"UpperTransmitPowerThreshold,omitempty"`
	Upstream                    bool  `json:"Upstream,omitempty"`
	Voltage                     int64 `json:"Voltage,omitempty"`
	UID                         int   `json:"uid,omitempty"`
}

type ResourceUsage struct {
	TotalMemory          int64           `json:"TotalMemory,omitempty"`
	FreeMemory           int64           `json:"FreeMemory,omitempty"`
	AvailableFlashMemory int64           `json:"AvailableFlashMemory,omitempty"`
	UsedFlashMemory      int64           `json:"UsedFlashMemory,omitempty"`
	CPUUsage             int64           `json:"CPUUsage,omitempty"`
	LoadAverage          float64         `json:"LoadAverage,omitempty"`
	LoadAverage5         float64         `json:"LoadAverage5,omitempty"`
	LoadAverage15        float64         `json:"LoadAverage15,omitempty"`
	ProcessStatus        ProcessStatuses `json:"ProcessStatus,omitempty"`
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
	PID         int    `json:"PID,string"`
	ProcessName string `json:"ProcessName"`
	Size        int64  `json:"Size,string"`
	Priority    int    `json:"Priority,string"`
	CPUTime     int64  `json:"CPUTime,string"`
	State       string `json:"State"`
}
