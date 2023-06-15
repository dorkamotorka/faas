package xdp

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// Program represents the necessary data structures for a simple XDP program that can filter traffic
// based on the attached rx queue.
type Program struct {
	Program *ebpf.Program
	Events  *ebpf.Map
}

// Attach the XDP Program to an interface.
func (p *Program) Attach(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.Program)
}

// Detach the XDP Program from an interface.
func (p *Program) Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

// Close closes and frees the resources allocated for the Program.
func (p *Program) Close() error {
	allErrors := []error{}
	if p.Events != nil {
		if err := p.Events.Close(); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close xsksMap: %v", err))
		}
		p.Events = nil
	}

	if p.Program != nil {
		if err := p.Program.Close(); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close XDP program: %v", err))
		}
		p.Program = nil
	}

	if len(allErrors) > 0 {
		return allErrors[0]
	}
	return nil
}

// removeProgram removes an existing XDP program from the given network interface.
func removeProgram(Ifindex int) error {
	var link netlink.Link
	var err error
	link, err = netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	if !isXdpAttached(link) {
		return nil
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}
	for {
		link, err = netlink.LinkByIndex(Ifindex)
		if err != nil {
			return err
		}
		if !isXdpAttached(link) {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

// attachProgram attaches the given XDP program to the network interface.
func attachProgram(Ifindex int, program *ebpf.Program) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	return netlink.LinkSetXdpFdWithFlags(link, program.FD(), int(DefaultXdpFlags))
}
