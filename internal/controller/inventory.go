// Package controller drives the agent across an estate: deploy, run, collect,
// correlate.
//
// Transport is delegated to the system ssh/scp binaries rather than a Go SSH
// library. That is a deliberate trade. A mixed estate is full of per-host keys,
// jump hosts, non-standard ports and agent forwarding, all of which are already
// described in ~/.ssh/config and already work. Reimplementing that configuration
// surface in Go means reimplementing its bugs; shelling out inherits every bit
// of it, including known_hosts verification, for free.
package controller

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Host is one target in the estate.
type Host struct {
	Host    string `yaml:"host"`
	User    string `yaml:"user,omitempty"`
	Port    int    `yaml:"port,omitempty"`
	Label   string `yaml:"label,omitempty"`
	Webroot string `yaml:"webroot,omitempty"`
	// AllSites scans every WordPress install found on the host rather than one.
	AllSites bool     `yaml:"all_sites,omitempty"`
	Packs    []string `yaml:"packs,omitempty"`
	// Extra flags appended verbatim to the remote agent invocation.
	Extra []string `yaml:"extra,omitempty"`
	// SSHOpts are extra options passed to ssh/scp (e.g. -J bastion).
	SSHOpts []string `yaml:"ssh_opts,omitempty"`
}

// Target renders the user@host form ssh expects.
func (h Host) Target() string {
	if h.User != "" {
		return h.User + "@" + h.Host
	}
	return h.Host
}

// Name is the display identity, preferring an operator label.
func (h Host) Name() string {
	if h.Label != "" {
		return h.Label
	}
	return h.Host
}

// Defaults are merged into every host that does not override them.
type Defaults struct {
	User     string   `yaml:"user,omitempty"`
	Port     int      `yaml:"port,omitempty"`
	Packs    []string `yaml:"packs,omitempty"`
	Profile  string   `yaml:"profile,omitempty"`
	AllSites bool     `yaml:"all_sites,omitempty"`
	Extra    []string `yaml:"extra,omitempty"`
	SSHOpts  []string `yaml:"ssh_opts,omitempty"`
}

type Inventory struct {
	Defaults Defaults `yaml:"defaults"`
	Hosts    []Host   `yaml:"hosts"`
}

// LoadInventory reads a YAML inventory, or a plain list of ssh targets — one
// per line, `user@host:port` — so a quick engagement does not require authoring
// a config file.
func LoadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "hosts:") || strings.HasPrefix(trimmed, "defaults:") {
		var inv Inventory
		if err := yaml.Unmarshal(b, &inv); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		inv.applyDefaults()
		return &inv, nil
	}

	var inv Inventory
	sc := bufio.NewScanner(strings.NewReader(trimmed))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, err := ParseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		inv.Hosts = append(inv.Hosts, h)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(inv.Hosts) == 0 {
		return nil, fmt.Errorf("%s: no hosts", path)
	}
	inv.applyDefaults()
	return &inv, nil
}

// ParseTarget accepts user@host, host:port, or user@host:port.
func ParseTarget(s string) (Host, error) {
	var h Host
	rest := s
	if i := strings.Index(rest, "@"); i >= 0 {
		h.User = rest[:i]
		rest = rest[i+1:]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		port, err := strconv.Atoi(rest[i+1:])
		if err != nil {
			return h, fmt.Errorf("bad port in %q", s)
		}
		h.Port = port
		rest = rest[:i]
	}
	if rest == "" {
		return h, fmt.Errorf("empty host in %q", s)
	}
	h.Host = rest
	return h, nil
}

func (inv *Inventory) applyDefaults() {
	d := inv.Defaults
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		if h.User == "" {
			h.User = d.User
		}
		if h.Port == 0 {
			h.Port = d.Port
		}
		if len(h.Packs) == 0 {
			h.Packs = d.Packs
		}
		if !h.AllSites {
			h.AllSites = d.AllSites
		}
		h.Extra = append(append([]string{}, d.Extra...), h.Extra...)
		h.SSHOpts = append(append([]string{}, d.SSHOpts...), h.SSHOpts...)
	}
}
