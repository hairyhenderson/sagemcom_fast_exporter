package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
)

//nolint:gochecknoglobals
var tracer = otel.Tracer("github.com/hairyhenderson/sagemcom_fast_exporter/collector")

type collector struct {
	ctx     context.Context
	scraper client.Scraper

	scrapeObserver ScrapeObserver

	sys       sysMetrics
	ethernet  ethMetrics
	optical   opticalMetrics
	resources resourcesMetrics
	wifiRadio wifiRadioMetrics
	wifiSSID  wifiSSIDMetrics
}

type sysMetrics struct {
	// deviceInfo
	uptime           *typedDesc
	memoryFreeBytes  *typedDesc
	memoryTotalBytes *typedDesc
	lastCrashDate    *typedDesc
	rebootCount      *typedDesc

	info *typedDesc
}

// results from getRessourcesUsage call
type resourcesMetrics struct {
	totalMemory          *typedDesc
	freeMemory           *typedDesc
	availableFlashMemory *typedDesc
	usedFlashMemory      *typedDesc
	cpuUsage             *typedDesc
	loadAverage          *typedDesc
	loadAverage5         *typedDesc
	loadAverage15        *typedDesc

	processInfo    *typedDesc
	processState   *typedDesc
	processSize    *typedDesc
	processCPUTime *typedDesc
}

// ethMetrics - metrics for Ethernet interfaces
type ethMetrics struct {
	// stats
	bcastPacketsRx   *typedDesc
	bcastPacketsTx   *typedDesc
	mcastPacketsRx   *typedDesc
	mcastPacketsTx   *typedDesc
	unicastPacketsRx *typedDesc
	unicastPacketsTx *typedDesc
	// total = mcast + bcast + ucast
	packetsRx *typedDesc
	packetsTx *typedDesc

	bytesRx          *typedDesc
	bytesTx          *typedDesc
	discardPacketsRx *typedDesc
	errorsRx         *typedDesc

	// TODO: track the rest

	// bitrate - interface bitrate in Mbps
	bitrate *typedDesc

	// UP, DOWN, etc
	status *typedDesc
	// info - const of 1 with interesting labels
	info *typedDesc
}

// opticalMetrics - metrics for optical interfaces
type opticalMetrics struct {
	// stats
	bcastPacketsRx   *typedDesc
	bcastPacketsTx   *typedDesc
	bytesRx          *typedDesc
	bytesTx          *typedDesc
	mcastPacketsRx   *typedDesc
	mcastPacketsTx   *typedDesc
	packetsRx        *typedDesc
	packetsTx        *typedDesc
	unicastPacketsRx *typedDesc
	unicastPacketsTx *typedDesc
	errorsRx         *typedDesc

	// other metrics
	// TODO: what unit is this? thousands of degree celsius?
	temperature *typedDesc

	upperOpticalThreshold       *typedDesc
	upperTransmitPowerThreshold *typedDesc
	voltage                     *typedDesc
	opticalSignalLevel          *typedDesc
	// this may be a timestamp?
	lastChange                  *typedDesc
	lowerOpticalThreshold       *typedDesc
	lowerTransmitPowerThreshold *typedDesc
	biasCurrent                 *typedDesc
	// UP, DOWN, etc
	status *typedDesc

	// info - const of 1 with interesting labels
	info *typedDesc
}

// per radio metrics
type wifiRadioMetrics struct {
	// Radio.Status
	radioStatus *typedDesc
	// info
	radioInfo *typedDesc
	// Radio.Channel
	channel *typedDesc
	// Radio.MaxBitRate (in Mib/s - convert to bps)
	maxBitRate *typedDesc
	// Radio.CurrentOperatingChannelBandwidth (string like "20MHz", "6GHZ", etc.)
	bandwidth *typedDesc
	// Radio.Stats.Noise (in dBm?)
	noise *typedDesc
	// Radios.TransmitPower (percentage i.e. divide by 100)
	transmitPower *typedDesc
	// Radios.TransmitPowerMax (in dBm)
	transmitPowerMax *typedDesc
	// Radios.LastChange (seconds since boot?)
	lastChange *typedDesc
}

// per SSID metrics
type wifiSSIDMetrics struct {
	// info - SSID.Name, SSID.Alias, SSID.Status, SSID.SSID (name), radio (infer by ifcName from SSID.LowerLayers)
	ssidInfo *typedDesc
	// SSID.Status
	ssidStatus *typedDesc

	packetsRx        *typedDesc
	packetsTx        *typedDesc
	bytesRx          *typedDesc
	bytesTx          *typedDesc
	bcastPacketsRx   *typedDesc
	bcastPacketsTx   *typedDesc
	mcastPacketsRx   *typedDesc
	mcastPacketsTx   *typedDesc
	unicastPacketsRx *typedDesc
	unicastPacketsTx *typedDesc
	discardPacketsRx *typedDesc
	discardPacketsTx *typedDesc
	errorsRx         *typedDesc
	errorsTx         *typedDesc
}

//nolint:funlen
func initEthMetrics(ns string) ethMetrics {
	ifaceLabels := []string{"name", "alias"}

	subsys := "ethernet"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}

	ifaceDesc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(
			buildName(name),
			help,
			ifaceLabels,
			nil,
		)
	}
	ifaceCounter := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ifaceDesc(name, help),
			valueType: prometheus.CounterValue,
		}
	}
	ifaceGauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ifaceDesc(name, help),
			valueType: prometheus.GaugeValue,
		}
	}

	return ethMetrics{
		bcastPacketsRx:   ifaceCounter("broadcast_rx_packets_total", "Number of broadcast packets received on this interface"),
		bcastPacketsTx:   ifaceCounter("broadcast_tx_packets_total", "Number of broadcast packets transmitted on this interface"),
		mcastPacketsRx:   ifaceCounter("multicast_rx_packets_total", "Number of multicast packets received on this interface"),
		mcastPacketsTx:   ifaceCounter("multicast_tx_packets_total", "Number of multicast packets transmitted on this interface"),
		unicastPacketsRx: ifaceCounter("unicast_rx_packets_total", "Number of unicast packets received on this interface"),
		unicastPacketsTx: ifaceCounter("unicast_tx_packets_total", "Number of unicast packets transmitted on this interface"),
		packetsRx:        ifaceCounter("rx_packets_total", "Total number of packets received on this interface"),
		packetsTx:        ifaceCounter("tx_packets_total", "Total number of packets transmitted on this interface"),

		bytesRx: ifaceCounter("rx_bytes_total", "Total number of bytes received on this interface"),
		bytesTx: ifaceCounter("tx_bytes_total", "Total number of bytes transmitted on this interface"),

		discardPacketsRx: ifaceCounter("rx_discarded_packets_total", "Number of received packets discarded on this interface"),
		errorsRx:         ifaceCounter("rx_errors_total", "Number of receive errors on this interface"),

		bitrate: ifaceGauge("bitrate", "Bit rate of this interface (bits per second)"),
		status:  ifaceGauge("status", "Status of this interface (0=UP, 1=DOWN, 2=UNKNOWN, 3=DORMANT, 4=NOTPRESENT, 5=LOWERLAYERDOWN, 6=ERROR)"),

		info: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("info"),
				"A metric with a constant '1' value labeled by various diagnostic interface information",
				[]string{
					"name", "alias", "cable_status",
					"current_duplex_mode", "mac_address", "role", "status",
				},
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
	}
}

//nolint:funlen
func initOpticalMetrics(ns string) opticalMetrics {
	ifaceLabels := []string{"name", "alias"}

	subsys := "optical"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}

	ifaceDesc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(
			buildName(name),
			help,
			ifaceLabels,
			nil,
		)
	}
	ifaceCounter := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ifaceDesc(name, help),
			valueType: prometheus.CounterValue,
		}
	}
	ifaceGauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ifaceDesc(name, help),
			valueType: prometheus.GaugeValue,
		}
	}

	return opticalMetrics{
		bcastPacketsRx:   ifaceCounter("broadcast_rx_packets_total", "Number of broadcast packets received on this interface"),
		bcastPacketsTx:   ifaceCounter("broadcast_tx_packets_total", "Number of broadcast packets transmitted on this interface"),
		mcastPacketsRx:   ifaceCounter("multicast_rx_packets_total", "Number of multicast packets received on this interface"),
		mcastPacketsTx:   ifaceCounter("multicast_tx_packets_total", "Number of multicast packets transmitted on this interface"),
		unicastPacketsRx: ifaceCounter("unicast_rx_packets_total", "Number of unicast packets received on this interface"),
		unicastPacketsTx: ifaceCounter("unicast_tx_packets_total", "Number of unicast packets transmitted on this interface"),
		packetsRx:        ifaceCounter("rx_packets_total", "Total number of packets received on this interface"),
		packetsTx:        ifaceCounter("tx_packets_total", "Total number of packets transmitted on this interface"),

		bytesRx: ifaceCounter("rx_bytes_total", "Total number of bytes received on this interface"),
		bytesTx: ifaceCounter("tx_bytes_total", "Total number of bytes transmitted on this interface"),

		errorsRx: ifaceCounter("rx_errors_total", "Number of receive errors on this interface"),

		status: ifaceGauge("status", "Status of this interface (0=UP, 1=DOWN, 2=UNKNOWN, 3=DORMANT, 4=NOTPRESENT, 5=LOWERLAYERDOWN, 6=ERROR)"),

		temperature: ifaceGauge("temperature_degrees_celsius", "Temperature of this interface"),

		upperOpticalThreshold: ifaceGauge("upper_optical_threshold", "Upper optical threshold of this interface"),
		upperTransmitPowerThreshold: ifaceGauge("upper_transmit_power_threshold",
			"Upper transmit power threshold of this interface"),
		voltage:            ifaceGauge("voltage_volts", "Voltage of this interface (volts)"),
		opticalSignalLevel: ifaceGauge("signal_level_dbm", "Optical signal level of this interface (dBm)"),
		lastChange:         ifaceGauge("last_change_timestamp", "Last change of this interface"),
		lowerOpticalThreshold: ifaceGauge("lower_optical_threshold",
			"Lower optical threshold of this interface"),
		lowerTransmitPowerThreshold: ifaceGauge("lower_transmit_power_threshold",
			"Lower transmit power threshold of this interface"),
		biasCurrent: ifaceGauge("bias_current", "Bias current of this interface (mA)"),

		info: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("info"),
				"A metric with a constant '1' value labeled by various diagnostic interface information",
				[]string{
					"name", "alias", "alarm",
					"part_number", "vendor_name", "status",
				},
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
	}
}

//nolint:funlen
func initResourcesMetrics(ns string) resourcesMetrics {
	procLabels := []string{"name", "pid"}

	subsys := "resources"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}

	procDesc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(
			buildName(name),
			help,
			procLabels,
			nil,
		)
	}
	procCounter := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      procDesc(name, help),
			valueType: prometheus.CounterValue,
		}
	}
	procGauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      procDesc(name, help),
			valueType: prometheus.GaugeValue,
		}
	}

	gauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      prometheus.NewDesc(buildName(name), help, nil, nil),
			valueType: prometheus.GaugeValue,
		}
	}

	return resourcesMetrics{
		totalMemory: gauge("total_memory_bytes", "Total memory available to the system"),
		freeMemory:  gauge("free_memory_bytes", "Free memory available to the system"),
		availableFlashMemory: gauge("available_flash_memory_bytes",
			"Available flash memory"),
		usedFlashMemory: gauge("used_flash_memory_bytes", "Used flash memory"),
		cpuUsage:        gauge("cpu_usage", "CPU usage (percentage)"),
		loadAverage:     gauge("load_average", "Load average"),
		loadAverage5:    gauge("load_average_5", "Load average (5 minutes)"),
		loadAverage15:   gauge("load_average_15", "Load average (15 minutes)"),

		processInfo: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("process_info"),
				"A metric with a constant '1' value labeled by various diagnostic process information",
				append(procLabels,
					"priority", "state"),
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
		processState: procGauge("process_state", "State of this process (0=RUNNING, 1=SLEEPING, 2=STOPPED, 3=ZOMBIE)"),
		processSize:  procGauge("process_size_bytes", "Size of this process (bytes)"),
		processCPUTime: procCounter("process_cpu_time_seconds",
			"CPU time of this process (seconds)"),
	}
}

func initSysMetrics(ns string) sysMetrics {
	subsys := "system"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}
	gauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      prometheus.NewDesc(buildName(name), help, nil, nil),
			valueType: prometheus.GaugeValue,
		}
	}

	return sysMetrics{
		uptime:           gauge("uptime_seconds", "System uptime (seconds)"),
		memoryFreeBytes:  gauge("memory_free_bytes", "Free memory available to the system"),
		memoryTotalBytes: gauge("memory_total_bytes", "Total memory available to the system"),
		lastCrashDate:    gauge("last_crash_date_timestamp", "Timestamp of the last crash"),
		rebootCount:      gauge("reboot_count", "Number of reboots"),
		info: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("device_info"),
				"A metric with a constant '1' value labeled by various device information",
				[]string{
					"additional_hardware_version", "additional_software_version", "backup_software_version",
					"country", "description", "external_firmware_version", "gui_api_version", "gui_firmware_version",
					"hardware_version", "internal_firmware_version", "mac_address", "manufacturer",
					"manufacturer_oui", "mode", "model_name", "model_number", "ont_serial_number",
					"product_class", "provisioning_code", "router_name", "software_version", "spec_version",
				},
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
	}
}

func initWiFiRadioMetrics(ns string) wifiRadioMetrics {
	radioLabels := []string{"name", "alias"}

	subsys := "wifi_radio"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}

	radioGauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc: prometheus.NewDesc(
				buildName(name),
				help,
				radioLabels,
				nil,
			),
			valueType: prometheus.GaugeValue,
		}
	}

	return wifiRadioMetrics{
		radioStatus: radioGauge("status", "Status of this radio (0=UP, 1=DOWN, 2=UNKNOWN, 3=DORMANT, 4=NOTPRESENT, 5=LOWERLAYERDOWN, 6=ERROR)"),
		radioInfo: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("info"),
				"A metric with a constant '1' value labeled by various radio information",
				append(radioLabels, "regulatory_domain", "supported_standards", "supported_bandwidth"),
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
		channel:          radioGauge("channel", "Current channel of this radio"),
		maxBitRate:       radioGauge("max_bit_rate_bytes_per_second", "Maximum bit rate of this radio (bytes per second)"),
		bandwidth:        radioGauge("bandwidth_hz", "Current bandwidth of this radio (Hz)"),
		noise:            radioGauge("noise_dbm", "Noise of this radio (dBm)"),
		transmitPower:    radioGauge("transmit_power_percentage", "Transmit power of this radio (percentage)"),
		transmitPowerMax: radioGauge("transmit_power_max_dbm", "Maximum transmit power of this radio (dBm)"),
		lastChange:       radioGauge("last_change_timestamp", "Last time the radio changed (seconds since boot)"),
	}
}

func initWiFiSSIDMetrics(ns string) wifiSSIDMetrics {
	ssidLabels := []string{"name", "alias", "ssid", "radio"}

	subsys := "wifi_ssid"

	buildName := func(name string) string {
		return prometheus.BuildFQName(ns, subsys, name)
	}

	ssidDesc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(
			buildName(name),
			help,
			ssidLabels,
			nil,
		)
	}
	ssidCounter := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ssidDesc(name, help),
			valueType: prometheus.CounterValue,
		}
	}
	ssidGauge := func(name, help string) *typedDesc {
		return &typedDesc{
			desc:      ssidDesc(name, help),
			valueType: prometheus.GaugeValue,
		}
	}

	return wifiSSIDMetrics{
		ssidInfo: &typedDesc{
			desc: prometheus.NewDesc(
				buildName("info"),
				"A metric with a constant '1' value labeled by various SSID information",
				append(ssidLabels, "status", "mac_address"),
				nil,
			),
			valueType: prometheus.GaugeValue,
		},
		ssidStatus: ssidGauge("status", "Status of this SSID (0=UP, 1=DOWN, 2=UNKNOWN, 3=DORMANT, 4=NOTPRESENT, 5=LOWERLAYERDOWN, 6=ERROR)"),

		packetsRx:        ssidCounter("rx_packets_total", "Total number of packets received on this SSID"),
		packetsTx:        ssidCounter("tx_packets_total", "Total number of packets transmitted on this SSID"),
		bytesRx:          ssidCounter("rx_bytes_total", "Total number of bytes received on this SSID"),
		bytesTx:          ssidCounter("tx_bytes_total", "Total number of bytes transmitted on this SSID"),
		bcastPacketsRx:   ssidCounter("broadcast_rx_packets_total", "Number of broadcast packets received on this SSID"),
		bcastPacketsTx:   ssidCounter("broadcast_tx_packets_total", "Number of broadcast packets transmitted on this SSID"),
		mcastPacketsRx:   ssidCounter("multicast_rx_packets_total", "Number of multicast packets received on this SSID"),
		mcastPacketsTx:   ssidCounter("multicast_tx_packets_total", "Number of multicast packets transmitted on this SSID"),
		unicastPacketsRx: ssidCounter("unicast_rx_packets_total", "Number of unicast packets received on this SSID"),
		unicastPacketsTx: ssidCounter("unicast_tx_packets_total", "Number of unicast packets transmitted on this SSID"),
		discardPacketsRx: ssidCounter("rx_discarded_packets_total", "Number of received packets discarded on this SSID"),
		discardPacketsTx: ssidCounter("tx_discarded_packets_total", "Number of transmitted packets discarded on this SSID"),
		errorsRx:         ssidCounter("rx_errors_total", "Number of receive errors on this SSID"),
		errorsTx:         ssidCounter("tx_errors_total", "Number of transmit errors on this SSID"),
	}
}

type ScrapeObserver interface {
	Observe(ctx context.Context, duration time.Duration, success bool)
}

func New(ctx context.Context, scraper client.Scraper, scrapeObserver ScrapeObserver) prometheus.Collector {
	ns := "sagemcom_fast"

	coll := &collector{
		ctx:     ctx,
		scraper: scraper,

		scrapeObserver: scrapeObserver,

		ethernet:  initEthMetrics(ns),
		optical:   initOpticalMetrics(ns),
		resources: initResourcesMetrics(ns),
		sys:       initSysMetrics(ns),
		wifiRadio: initWiFiRadioMetrics(ns),
		wifiSSID:  initWiFiSSIDMetrics(ns),
	}

	return coll
}

func (c *collector) Describe(_ chan<- *prometheus.Desc) {
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()

	start := time.Now()

	err := c.update(ctx, ch)
	if err != nil {
		slog.Default().ErrorContext(ctx, "update error", "err", err)
	}

	c.scrapeObserver.Observe(ctx, time.Since(start), err == nil)
}

func (c *collector) update(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx, span := tracer.Start(ctx, "collector.update")
	defer span.End()

	slog.DebugContext(ctx, "getting Device value")

	v, err := c.scraper.GetValue(ctx, "Device")
	if err != nil {
		slog.ErrorContext(ctx, "update getValue errored", "err", err)

		return fmt.Errorf("getValue: %w", err)
	}

	slog.DebugContext(ctx, "getting resource usage")

	r, err := c.scraper.GetResourceUsage(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "update getResourceUsage errored", "err", err)

		return fmt.Errorf("getResourceUsage: %w", err)
	}

	slog.DebugContext(ctx, "got resources, updating metrics")
	c.updateResources(ch, r)

	d := v.Device

	slog.DebugContext(ctx, "got device, updating metrics")

	for _, iface := range d.Ethernet.Interfaces {
		if !iface.Enable {
			continue
		}

		c.updateEthernet(ch, iface)
	}

	for _, iface := range d.Optical.Interfaces {
		c.updateOptical(ch, iface)
	}

	radioNameToIfcName := map[string]string{}
	for _, radio := range d.WiFi.Radios {
		radioNameToIfcName[radio.Name] = radio.IfcName

		c.updateWiFiRadio(ch, radio)
	}

	for _, ssid := range d.WiFi.SSIDs {
		c.updateWiFiSSID(ch, ssid, radioNameToIfcName)
	}

	c.updateSys(ch, d.DeviceInfo)

	return nil
}

func statusNum(status string) int {
	switch status {
	case "UP":
		return 0
	case "DOWN":
		return 1
	case "UNKNOWN":
		return 2
	case "DORMANT":
		return 3
	case "NOTPRESENT":
		return 4
	case "LOWERLAYERDOWN":
		return 5
	case "ERROR":
		return 6
	default:
		return 1
	}
}

func (c *collector) updateEthernet(ch chan<- prometheus.Metric, iface client.EthernetInterface) {
	m := c.ethernet
	labelValues := []string{iface.IfcName, iface.Alias}

	// convert from Mbps to bps
	bitrate := iface.CurrentBitRate * 1000 * 1000
	ch <- recordNum(m.bitrate, bitrate, labelValues...)

	// stats metrics
	ch <- recordNum(m.bcastPacketsRx, iface.Stats.BroadcastPacketsReceived, labelValues...)

	ch <- recordNum(m.bcastPacketsTx, iface.Stats.BroadcastPacketsSent, labelValues...)

	ch <- recordNum(m.mcastPacketsRx, iface.Stats.MulticastPacketsReceived, labelValues...)

	ch <- recordNum(m.mcastPacketsTx, iface.Stats.MulticastPacketsSent, labelValues...)

	ch <- recordNum(m.unicastPacketsRx, iface.Stats.UnicastPacketsReceived, labelValues...)

	ch <- recordNum(m.unicastPacketsTx, iface.Stats.UnicastPacketsSent, labelValues...)

	ch <- recordNum(m.packetsRx, iface.Stats.PacketsReceived, labelValues...)

	ch <- recordNum(m.packetsTx, iface.Stats.PacketsSent, labelValues...)

	ch <- recordNum(m.bytesRx, iface.Stats.BytesReceived, labelValues...)

	ch <- recordNum(m.bytesTx, iface.Stats.BytesSent, labelValues...)

	ch <- recordNum(m.discardPacketsRx, iface.Stats.DiscardPacketsReceived, labelValues...)

	ch <- recordNum(m.errorsRx, iface.Stats.ErrorsReceived, labelValues...)

	ch <- recordNum(m.status, statusNum(iface.Status), labelValues...)

	ch <- recordNum(m.info, 1, append(labelValues,
		iface.Diagnostics.CableStatus, iface.Diagnostics.CurrentDuplexMode,
		iface.MACAddress, iface.Role, iface.Status)...)
}

func (c *collector) updateOptical(ch chan<- prometheus.Metric, iface client.OpticalInterface) {
	m := c.optical
	labelValues := []string{iface.IfcName, iface.Alias}

	// stats metrics
	ch <- recordNum(m.bcastPacketsRx, iface.Stats.BroadcastPacketsReceived, labelValues...)

	ch <- recordNum(m.bcastPacketsTx, iface.Stats.BroadcastPacketsSent, labelValues...)

	ch <- recordNum(m.mcastPacketsRx, iface.Stats.MulticastPacketsReceived, labelValues...)

	ch <- recordNum(m.mcastPacketsTx, iface.Stats.MulticastPacketsSent, labelValues...)

	ch <- recordNum(m.unicastPacketsRx, iface.Stats.UnicastPacketsReceived, labelValues...)

	ch <- recordNum(m.unicastPacketsTx, iface.Stats.UnicastPacketsSent, labelValues...)

	ch <- recordNum(m.packetsRx, iface.Stats.PacketsReceived, labelValues...)

	ch <- recordNum(m.packetsTx, iface.Stats.PacketsSent, labelValues...)

	ch <- recordNum(m.bytesRx, iface.Stats.BytesReceived, labelValues...)

	ch <- recordNum(m.bytesTx, iface.Stats.BytesSent, labelValues...)

	// ch <- recordNum(m.discardPacketsRx, iface.Stats.DiscardPacketsReceived, labelValues...)

	ch <- recordNum(m.errorsRx, iface.Stats.ErrorsReceived, labelValues...)

	// other metrics
	ch <- recordNum(m.temperature, iface.Temperature, labelValues...)

	ch <- recordNum(m.upperOpticalThreshold, iface.UpperOpticalThreshold, labelValues...)

	ch <- recordNum(m.lowerOpticalThreshold, iface.LowerOpticalThreshold, labelValues...)

	ch <- recordNum(m.upperTransmitPowerThreshold, iface.UpperTransmitPowerThreshold, labelValues...)

	ch <- recordNum(m.lowerTransmitPowerThreshold, iface.LowerTransmitPowerThreshold, labelValues...)

	ch <- recordNum(m.opticalSignalLevel, iface.OpticalSignalLevel, labelValues...)

	ch <- recordNum(m.voltage, iface.Voltage, labelValues...)

	ch <- recordNum(m.biasCurrent, iface.BIASCurrent, labelValues...)

	ch <- recordNum(m.lastChange, iface.LastChange, labelValues...)

	ch <- recordNum(m.status, statusNum(iface.Status), labelValues...)

	ch <- recordNum(m.info, 1, append(labelValues,
		iface.Alarm, iface.OpticalPartNumber, iface.OpticalVendorName, iface.Status)...)
}

func (c *collector) updateWiFiRadio(ch chan<- prometheus.Metric, radio client.Radio) {
	m := c.wifiRadio

	labelValues := []string{radio.IfcName, radio.Alias}
	ch <- recordNum(m.radioInfo, 1, append(labelValues, radio.RegulatoryDomain, radio.SupportedStandards, radio.SupportedChannelBandwidth)...)

	ch <- recordNum(m.radioStatus, statusNum(radio.Status), labelValues...)

	ch <- recordNum(m.channel, radio.Channel, labelValues...)

	ch <- recordNum(m.maxBitRate, radio.MaxBitRate, labelValues...)

	ch <- recordNum(m.bandwidth, radio.CurrentOperatingChannelBandwidth, labelValues...)

	ch <- recordNum(m.noise, radio.Stats.Noise, labelValues...)

	ch <- recordNum(m.transmitPower, radio.TransmitPower, labelValues...)

	ch <- recordNum(m.transmitPowerMax, radio.TransmitPowerMax, labelValues...)

	ch <- recordNum(m.lastChange, radio.LastChange, labelValues...)
}

func (c *collector) updateWiFiSSID(ch chan<- prometheus.Metric, ssid client.SSID, radioNameToIfcName map[string]string) {
	m := c.wifiSSID

	labelValues := []string{ssid.IfcName, ssid.Alias, ssid.SSID, radioNameToIfcName[ssid.LowerLayers]}

	ch <- recordNum(m.ssidInfo, 1, append(labelValues, ssid.Status, ssid.MACAddress)...)

	ch <- recordNum(m.ssidStatus, statusNum(ssid.Status), labelValues...)

	ch <- recordNum(m.packetsRx, ssid.Stats.PacketsReceived, labelValues...)

	ch <- recordNum(m.packetsTx, ssid.Stats.PacketsSent, labelValues...)

	ch <- recordNum(m.bytesRx, ssid.Stats.BytesReceived, labelValues...)

	ch <- recordNum(m.bytesTx, ssid.Stats.BytesSent, labelValues...)

	ch <- recordNum(m.bcastPacketsRx, ssid.Stats.BroadcastPacketsReceived, labelValues...)

	ch <- recordNum(m.bcastPacketsTx, ssid.Stats.BroadcastPacketsSent, labelValues...)

	ch <- recordNum(m.mcastPacketsRx, ssid.Stats.MulticastPacketsReceived, labelValues...)

	ch <- recordNum(m.mcastPacketsTx, ssid.Stats.MulticastPacketsSent, labelValues...)

	ch <- recordNum(m.unicastPacketsRx, ssid.Stats.UnicastPacketsReceived, labelValues...)

	ch <- recordNum(m.unicastPacketsTx, ssid.Stats.UnicastPacketsSent, labelValues...)

	ch <- recordNum(m.discardPacketsRx, ssid.Stats.DiscardPacketsReceived, labelValues...)

	ch <- recordNum(m.discardPacketsTx, ssid.Stats.DiscardPacketsSent, labelValues...)

	ch <- recordNum(m.errorsRx, ssid.Stats.ErrorsReceived, labelValues...)

	ch <- recordNum(m.errorsTx, ssid.Stats.ErrorsSent, labelValues...)
}

func (c *collector) updateResources(ch chan<- prometheus.Metric, r *client.ResourceUsage) {
	m := c.resources

	// these are all in KiB, convert to bytes
	ch <- recordNum(m.totalMemory, r.TotalMemory*1024)

	ch <- recordNum(m.freeMemory, r.FreeMemory*1024)

	ch <- recordNum(m.availableFlashMemory, r.AvailableFlashMemory*1024)

	ch <- recordNum(m.usedFlashMemory, r.UsedFlashMemory*1024)

	// convert from percentage to decimal
	ch <- recordNum(m.cpuUsage, float64(r.CPUUsage)/100)

	ch <- recordNum(m.loadAverage, r.LoadAverage)

	ch <- recordNum(m.loadAverage5, r.LoadAverage5)

	ch <- recordNum(m.loadAverage15, r.LoadAverage15)

	for _, proc := range r.ProcessStatus {
		procLabels := []string{proc.ProcessName, strconv.Itoa(proc.PID)}
		// size is in KiB, convert to bytes
		ch <- recordNum(m.processSize, proc.Size*1024, procLabels...)

		// CPU time is in milliseconds (I _think?_), convert to seconds
		ch <- recordNum(m.processCPUTime, float64(proc.CPUTime)/1000, procLabels...)

		state := int64(0)

		switch proc.State {
		case "RUNNING":
			state = 0
		case "SLEEPING":
			state = 1
		case "STOPPED":
			state = 2
		case "ZOMBIE":
			state = 3
		}

		ch <- recordNum(m.processState, state, procLabels...)

		ch <- recordNum(m.processInfo, 1, append(procLabels, strconv.Itoa(proc.Priority), proc.State)...)
	}
}

func (c *collector) updateSys(ch chan<- prometheus.Metric, di client.DeviceInfo) {
	m := c.sys

	ch <- recordNum(m.uptime, di.UpTime)

	ch <- recordNum(m.lastCrashDate, di.CrashHistory.LastCrashDate.Unix())

	ch <- recordNum(m.rebootCount, di.RebootCount)

	// memory is in KiB, convert to bytes
	ch <- recordNum(m.memoryFreeBytes, di.MemoryStatus.Free*1024)

	ch <- recordNum(m.memoryTotalBytes, di.MemoryStatus.Total*1024)

	ch <- recordNum(m.info, 1, []string{
		di.AdditionalHardwareVersion,
		di.AdditionalSoftwareVersion,
		di.BackupSoftwareVersion,
		di.Country,
		di.Description,
		di.ExternalFirmwareVersion,
		di.GUIAPIVersion,
		di.GUIFirmwareVersion,
		di.HardwareVersion,
		di.InternalFirmwareVersion,
		di.MACAddress,
		di.Manufacturer,
		di.ManufacturerOUI,
		di.Mode,
		di.ModelName,
		di.ModelNumber,
		di.ONTSerialNumber,
		di.ProductClass,
		di.ProvisioningCode,
		di.RouterName,
		di.SoftwareVersion,
		di.SpecVersion,
	}...)
}

// from node_exporter - we want to expose counters, but we can't simply
// increment them, so we're just going to wrap
type typedDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

// generic version
func recordNum[T float64 | int | int64](d *typedDesc, value T, labels ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(d.desc, d.valueType, float64(value), labels...)
}
