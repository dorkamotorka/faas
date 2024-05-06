// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type coldyTcpSessionKey struct {
	Sport uint16
	Dport uint16
	Saddr uint32
}

// loadColdy returns the embedded CollectionSpec for coldy.
func loadColdy() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ColdyBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load coldy: %w", err)
	}

	return spec, err
}

// loadColdyObjects loads coldy and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*coldyObjects
//	*coldyPrograms
//	*coldyMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadColdyObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadColdy()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// coldySpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type coldySpecs struct {
	coldyProgramSpecs
	coldyMapSpecs
}

// coldySpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type coldyProgramSpecs struct {
	TcEgress   *ebpf.ProgramSpec `ebpf:"tc_egress"`
	XdpIngress *ebpf.ProgramSpec `ebpf:"xdp_ingress"`
}

// coldyMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type coldyMapSpecs struct {
	Events   *ebpf.MapSpec `ebpf:"events"`
	Sessions *ebpf.MapSpec `ebpf:"sessions"`
}

// coldyObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadColdyObjects or ebpf.CollectionSpec.LoadAndAssign.
type coldyObjects struct {
	coldyPrograms
	coldyMaps
}

func (o *coldyObjects) Close() error {
	return _ColdyClose(
		&o.coldyPrograms,
		&o.coldyMaps,
	)
}

// coldyMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadColdyObjects or ebpf.CollectionSpec.LoadAndAssign.
type coldyMaps struct {
	Events   *ebpf.Map `ebpf:"events"`
	Sessions *ebpf.Map `ebpf:"sessions"`
}

func (m *coldyMaps) Close() error {
	return _ColdyClose(
		m.Events,
		m.Sessions,
	)
}

// coldyPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadColdyObjects or ebpf.CollectionSpec.LoadAndAssign.
type coldyPrograms struct {
	TcEgress   *ebpf.Program `ebpf:"tc_egress"`
	XdpIngress *ebpf.Program `ebpf:"xdp_ingress"`
}

func (p *coldyPrograms) Close() error {
	return _ColdyClose(
		p.TcEgress,
		p.XdpIngress,
	)
}

func _ColdyClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed coldy_bpfeb.o
var _ColdyBytes []byte
