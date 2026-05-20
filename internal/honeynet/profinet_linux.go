//go:build linux

package honeynet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// startProfinetDCP opens an AF_PACKET socket, listens for PROFINET-DCP
// Identify requests (EtherType 0x8892, FrameID 0xFEFE), and for each one
// reports the probe (detection) and answers with a DCP Identify response
// per matching virtual station (deception). Returns when ctx is cancelled.
func startProfinetDCP(ctx context.Context, cfg ProfinetCfg, topo *Topology, onProbe ProbeFunc) error {
	stations := collectPNStations(topo)
	if len(stations) == 0 {
		return errors.New("profinet_responder: no industrial honeynet hosts configured")
	}
	iface, err := pickInterface(cfg.Interface)
	if err != nil {
		return err
	}
	const ethPALL = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("profinet_responder: need CAP_NET_RAW: %w", err)
		}
		return fmt.Errorf("profinet_responder: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethTypePROFINET),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("profinet_responder: bind: %w", err)
	}

	slog.Info("honeynet profinet-dcp responder up",
		"interface", iface.Name, "stations", len(stations))

	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 1600)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINTR) {
				return nil
			}
			slog.Warn("profinet_responder: recvfrom", "err", err)
			continue
		}
		reqMAC, xid, nameFilter, ok := parseDCPIdentify(buf[:n])
		if !ok {
			continue
		}
		if onProbe != nil {
			meta := map[string]any{"xid": xid}
			if nameFilter != "" {
				meta["name_filter"] = nameFilter
			} else {
				meta["scope"] = "identify-all"
			}
			onProbe(macString(reqMAC), meta)
		}
		for _, st := range stationsForRequest(stations, nameFilter) {
			frame := buildDCPIdentifyResponse(st, reqMAC, xid)
			if err := sendPNFrame(fd, iface.Index, reqMAC, frame); err != nil {
				slog.Debug("profinet_responder: send", "err", err)
			}
		}
	}
}

func sendPNFrame(fd, ifIndex int, dstMAC [6]byte, frame []byte) error {
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(ethTypePROFINET),
		Ifindex:  ifIndex,
		Halen:    6,
	}
	copy(sa.Addr[:], dstMAC[:])
	return unix.Sendto(fd, frame, 0, sa)
}

func macString(m [6]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 17)
	for i, b := range m {
		out[i*3] = hex[b>>4]
		out[i*3+1] = hex[b&0x0F]
		if i < 5 {
			out[i*3+2] = ':'
		}
	}
	return string(out[:17])
}
