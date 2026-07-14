package main

// Semver/latest helpers: enough Go/SemVer parsing and ordering to answer the
// proxy's "/@v/list" and "/@latest" endpoints from the versions actually
// present in the repository.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	semverRE     = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?(?:\+incompatible)?$`)
	pseudoTimeRE = regexp.MustCompile(`(?:^|[-.])([0-9]{14})-[0-9A-Fa-f]{7,}$`)
)

type parsedSemver struct {
	ok                  bool
	major, minor, patch int64
	pre                 string
}

func parseSemver(v string) parsedSemver {
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return parsedSemver{}
	}
	maj, _ := strconv.ParseInt(m[1], 10, 64)
	minr, _ := strconv.ParseInt(m[2], 10, 64)
	pat, _ := strconv.ParseInt(m[3], 10, 64)
	return parsedSemver{ok: true, major: maj, minor: minr, patch: pat, pre: m[4]}
}

func isValidSemver(v string) bool { return parseSemver(v).ok }

func isPseudoVersion(v string) bool { return pseudoTimeRE.MatchString(v) }

func compareVersions(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	if !pa.ok && !pb.ok {
		return strings.Compare(a, b)
	}
	if !pa.ok {
		return -1
	}
	if !pb.ok {
		return 1
	}
	for _, pair := range [][2]int64{{pa.major, pb.major}, {pa.minor, pb.minor}, {pa.patch, pb.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	// Release > pre-release.
	if pa.pre == "" && pb.pre != "" {
		return 1
	}
	if pa.pre != "" && pb.pre == "" {
		return -1
	}
	return comparePrerelease(pa.pre, pb.pre)
}

func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		if c := comparePrereleaseIdent(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return 0
}

// comparePrereleaseIdent orders a single dot-separated pre-release identifier.
// Numeric identifiers compare numerically and rank below alphanumeric ones.
func comparePrereleaseIdent(a, b string) int {
	ai, aErr := strconv.ParseInt(a, 10, 64)
	bi, bErr := strconv.ParseInt(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		default:
			return 0
		}
	case aErr == nil: // numeric identifiers have lower precedence
		return -1
	case bErr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func sortVersionsAsc(vs []string) {
	sort.Slice(vs, func(i, j int) bool { return compareVersions(vs[i], vs[j]) < 0 })
}

func filterNonPseudoValid(vs []string) []string {
	out := make([]string, 0, len(vs))
	seen := map[string]bool{}
	for _, v := range vs {
		if !seen[v] && isValidSemver(v) && !isPseudoVersion(v) {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

func chooseLatest(infos []ModuleInfo) (ModuleInfo, bool) {
	var releases, pres, pseudos []ModuleInfo
	for _, info := range infos {
		v := info.Version
		if isPseudoVersion(v) {
			pseudos = append(pseudos, info)
			continue
		}
		p := parseSemver(v)
		if !p.ok {
			continue
		}
		if p.pre == "" {
			releases = append(releases, info)
		} else {
			pres = append(pres, info)
		}
	}
	sortInfoVersionDesc := func(xs []ModuleInfo) {
		sort.Slice(xs, func(i, j int) bool { return compareVersions(xs[i].Version, xs[j].Version) > 0 })
	}
	if len(releases) > 0 {
		sortInfoVersionDesc(releases)
		return releases[0], true
	}
	if len(pres) > 0 {
		sortInfoVersionDesc(pres)
		return pres[0], true
	}
	if len(pseudos) > 0 {
		sort.Slice(pseudos, func(i, j int) bool { return pseudos[i].Time.After(pseudos[j].Time) })
		return pseudos[0], true
	}
	return ModuleInfo{}, false
}
