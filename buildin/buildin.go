// Package buildin ships the curated source definitions the low-side UI offers
// as ready-made picks for the apt and rpm ecosystems, so operators can mirror
// common distributions without hunting down the right sources.list or .repo
// content themselves. The definitions live as plain files under apt/ and rpm/
// in this directory and are embedded into the binary; picking one in the UI
// pastes its content into the ecosystem's collect input, where it works for a
// single run or a schedule alike.
package buildin

import (
	"embed"
	"fmt"
)

//go:embed apt/*.sources rpm/*.repo
var files embed.FS

// Entry is one built-in source definition, ready to paste into the collect
// form of its ecosystem.
type Entry struct {
	Label   string `json:"label"`
	File    string `json:"file"`
	Content string `json:"content"`
}

// catalog lists the built-in files per ecosystem stream in the order the UI
// presents them (newest release first). Every embedded file must appear here
// exactly once — buildin_test.go enforces the pairing.
func catalog() map[string][]Entry {
	return map[string][]Entry{
		"apt": {
			{Label: "Ubuntu 26.04 LTS (resolute) - full archive", File: "apt/ubuntu_resolute_full.sources"},
			{Label: "Ubuntu 26.04 LTS (resolute) - main component only", File: "apt/ubuntu_resolute_main.sources"},
			{Label: "Ubuntu 26.04 LTS (resolute) - security updates only", File: "apt/ubuntu_resolute_security.sources"},
			{Label: "Ubuntu 24.04 LTS (noble) - full archive", File: "apt/ubuntu_noble_full.sources"},
			{Label: "Ubuntu 24.04 LTS (noble) - main component only", File: "apt/ubuntu_noble_main.sources"},
			{Label: "Ubuntu 24.04 LTS (noble) - security updates only", File: "apt/ubuntu_noble_security.sources"},
			{Label: "Ubuntu 22.04 LTS (jammy) - full archive", File: "apt/ubuntu_jammy_full.sources"},
			{Label: "Ubuntu 22.04 LTS (jammy) - main component only", File: "apt/ubuntu_jammy_main.sources"},
			{Label: "Ubuntu 22.04 LTS (jammy) - security updates only", File: "apt/ubuntu_jammy_security.sources"},
			{Label: "Docker CE - Ubuntu 26.04 (resolute)", File: "apt/docker_ce_resolute.sources"},
			{Label: "Docker CE - Ubuntu 24.04 (noble)", File: "apt/docker_ce_noble.sources"},
			{Label: "Docker CE - Ubuntu 22.04 (jammy)", File: "apt/docker_ce_jammy.sources"},
		},
		"rpm": {
			{Label: "Rocky Linux 10 - BaseOS, AppStream, CRB and extras", File: "rpm/rocky10_full.repo"},
			{Label: "Rocky Linux 10 - BaseOS", File: "rpm/rocky10_baseos.repo"},
			{Label: "Rocky Linux 10 - AppStream", File: "rpm/rocky10_appstream.repo"},
			{Label: "Rocky Linux 10 - CRB", File: "rpm/rocky10_crb.repo"},
			{Label: "Rocky Linux 10 - extras", File: "rpm/rocky10_extras.repo"},
			{Label: "Rocky Linux 9 - BaseOS, AppStream, CRB and extras", File: "rpm/rocky9_full.repo"},
			{Label: "Rocky Linux 9 - BaseOS", File: "rpm/rocky9_baseos.repo"},
			{Label: "Rocky Linux 9 - AppStream", File: "rpm/rocky9_appstream.repo"},
			{Label: "Rocky Linux 9 - CRB", File: "rpm/rocky9_crb.repo"},
			{Label: "Rocky Linux 9 - extras", File: "rpm/rocky9_extras.repo"},
			{Label: "Docker CE - EL10 (Rocky/RHEL 10)", File: "rpm/docker_ce_el10.repo"},
			{Label: "Docker CE - EL9 (Rocky/RHEL 9)", File: "rpm/docker_ce_el9.repo"},
		},
	}
}

// Sources returns the built-in source definitions keyed by ecosystem stream,
// each list in presentation order with the file contents filled in.
func Sources() (map[string][]Entry, error) {
	cat := catalog()
	for stream, entries := range cat {
		for i := range entries {
			b, err := files.ReadFile(entries[i].File)
			if err != nil {
				return nil, fmt.Errorf("read built-in %s source %s: %w", stream, entries[i].File, err)
			}
			entries[i].Content = string(b)
		}
	}
	return cat, nil
}
