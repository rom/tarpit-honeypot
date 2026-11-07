// Package otclass is the single source of truth for which protocol handlers are
// operational-technology — ICS/SCADA, building automation (BAS/BMS), and
// clinical/medical (medtech). It exists so every part of the sensor agrees on
// what "OT" means: the enricher stamps a unified `ot` flag + `meta:ot` label and
// an `ics-ot` / `healthcare` targeting value on these events, independent of the
// source IP (OT lives on RFC1918 segments), and the recognition layer keys its
// OT-recon composite off the same set.
package otclass

// Class is the OT sub-domain of a handler.
type Class string

const (
	None    Class = ""
	ICS     Class = "ics"     // SCADA / PLC / RTU / safety / power / historian / fieldbus
	BAS     Class = "bas"     // building automation & control, HVAC, lighting, access, metering
	MedTech Class = "medtech" // clinical / medical devices & systems
)

// handlerClass maps a handler name (as used in listeners[].handler) to its OT
// sub-domain. Keep in sync with internal/listener/handler registrations and
// docs/ot.md §2. UDP/TLS variants and aliases are listed explicitly so the
// classification never depends on string munging.
var handlerClass = map[string]Class{
	// --- ICS / SCADA / process control -----------------------------------
	"modbus": ICS, "modbus_security": ICS, "modbuss": ICS, "modbus_udp": ICS,
	"s7": ICS, "s7comm_plus": ICS,
	"iec104": ICS, "dnp3": ICS, "dnp3_udp": ICS,
	"ethernetip": ICS, "enip_udp": ICS, "cip_io": ICS,
	"opcua": ICS, "opcua_pubsub": ICS, "opcua_session": ICS, "opcua_state": ICS,
	"codesys": ICS, "proconos": ICS, "pcworx": ICS,
	"melsec": ICS, "slmp": ICS,
	"fins": ICS, "fins_tcp": ICS,
	"ads": ICS, "ads_discovery": ICS, "ethercat": ICS,
	"profinet": ICS, "powerlink": ICS, "ff_hse": ICS, "saia_sbus": ICS,
	"hartip": ICS, "hartip_udp": ICS, "atg": ICS,
	"bsap": ICS, "ge_srtp": ICS, "gesrtp": ICS, "ge_egd": ICS, "roc_plus": ICS,
	"pcom": ICS, "pcom_udp": ICS,
	"c37118": ICS, "synchrophasor": ICS, "siprotec_en100": ICS, "siprotec": ICS,
	"tristation": ICS, "iccp_secure": ICS, "mms": ICS,
	"dlms": ICS, "c1222": ICS, "dds_rtps": ICS, "wdbrpc": ICS,
	"crimson": ICS, "focas": ICS, "secs_gem": ICS,
	"osisoft_pi": ICS, "aspen_ip21": ICS, "proficy_historian": ICS, "canary_historian": ICS,
	"modbus_deep": ICS, "dnp3_state": ICS, "s7comm": ICS, "historian": ICS,

	// --- Building automation / BMS / BAS ---------------------------------
	"bacnet": BAS, "bacnet_sc": BAS, "bacnet_scs": BAS,
	"knx": BAS, "lontalk": BAS, "fox": BAS,
	"cbus": BAS, "crestron": BAS, "amx_netlinx": BAS, "vantage": BAS, "loxone": BAS,
	"pjlink": BAS, "osdp": BAS, "mbus": BAS,
	"danfoss_aksm": BAS, "danfoss_aksms": BAS,
	"dixell": BAS, "carel": BAS, "trane": BAS, "resideo": BAS,
	"niagara_platform": BAS, "obix": BAS, "enocean": BAS,

	// --- Medical / clinical (medtech) ------------------------------------
	"hl7": MedTech, "hl7s": MedTech, "dicom": MedTech, "dicoms": MedTech,
	"astm": MedTech, "poct1": MedTech, "fhir": MedTech, "fhirs": MedTech,
}

// Of returns the OT sub-domain of a handler, or None when it is not OT.
func Of(handler string) Class { return handlerClass[handler] }

// IsOT reports whether a handler is any flavour of operational technology
// (ICS, building automation, or medical).
func IsOT(handler string) bool { return handlerClass[handler] != None }

// Targeting is the coarse "what are they hunting" value for an OT handler,
// matching the enricher's targeting vocabulary: ICS/BAS → "ics-ot", medical →
// "healthcare". "" for a non-OT handler.
func Targeting(handler string) string {
	switch handlerClass[handler] {
	case ICS, BAS:
		return "ics-ot"
	case MedTech:
		return "healthcare"
	}
	return ""
}
