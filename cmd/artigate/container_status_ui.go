package main

import (
	"fmt"
	"sort"
	"time"
)

func containerDiscoveryDetailFields(status ContainerDiscoveryStatus) []UIDetailField {
	label := "Unknown — collect again to record attachment discovery"
	if status.State == "complete" {
		label = "Complete — attachment discovery finished"
	} else if status.State == "incomplete" {
		label = "Incomplete — retry collection; known attachments are retained"
	}
	fields := []UIDetailField{{Label: "Attachment discovery", Value: label}}
	if status.CheckedAt != "" {
		fields = append(fields,
			UIDetailField{Label: "Discovery observation exported", Value: status.CheckedAt},
			UIDetailField{Label: "Artifacts collected in this observation", Value: fmt.Sprint(status.Artifacts)},
			UIDetailField{Label: "Subjects checked", Value: fmt.Sprint(status.Subjects)},
		)
	}
	if status.LastSuccessAt != "" {
		fields = append(fields, UIDetailField{Label: "Last complete discovery", Value: status.LastSuccessAt})
	}
	for _, issue := range status.Issues {
		message := containerDiscoveryIssueMessage(issue.Code)
		if issue.Subject != "" {
			message += " (" + shortDigest(issue.Subject) + ")"
		}
		fields = append(fields, UIDetailField{Label: "Discovery issue", Value: message})
	}
	if status.IssuesDropped > 0 {
		fields = append(fields, UIDetailField{Label: "Additional discovery issues", Value: fmt.Sprint(status.IssuesDropped)})
	}
	return fields
}

func containerDiscoveryIssueMessage(code string) string {
	switch code {
	case "referrers_api":
		return "Referrer lookup failed or returned an incomplete response"
	case "referrers_fallback":
		return "Fallback referrer lookup failed"
	case "legacy_fetch":
		return "Legacy signature or attestation lookup failed"
	case "artifact_fetch":
		return "An attachment or required child could not be downloaded"
	case "artifact_invalid":
		return "An attachment failed content or subject validation"
	case "discovery_limit":
		return "Attachment discovery reached a configured limit"
	case "cancelled":
		return "Attachment discovery was canceled"
	default:
		return "Attachment discovery could not be completed"
	}
}

// collectContainerDiscoveryMetrics uses only bounded state/code labels. Image
// digests, repository names and failure messages belong in the status API.
// Alert: sum(artigate_low_container_discovery_current_records{state="incomplete"}) > 0
// Alert: sum(artigate_low_container_discovery_current_records{freshness="stale"}) > 0
func (s *LowServer) collectContainerDiscoveryMetrics(p *promWriter) {
	records, err := s.containerDiscoveryRecords()
	readError := float64(0)
	if err != nil {
		readError = 1
	}
	p.metric("artigate_low_container_discovery_status_read_error", "gauge",
		"1 when durable container attachment discovery status could not be read.", readError)
	if err != nil {
		return
	}
	writeContainerDiscoveryMetrics(p, records)
	writeContainerDiscoveryCurrentMetrics(p, records)
}

// Current-reference alerts deliberately exclude retained historical observations.
// Existing all-history gauges keep their meaning for compatible dashboards.
func writeContainerDiscoveryCurrentMetrics(p *promWriter, records []ContainerDiscoveryRecord) {
	type key struct{ lifecycle, state, freshness string }
	counts := make(map[key]int)
	for _, record := range records {
		state := containerDiscoveryUnknown
		if record.Discovery != nil {
			state = normalizedContainerDiscoveryState(record.Discovery.State)
		}
		counts[key{lifecycle: record.Lifecycle, state: state}]++
		if record.Lifecycle == "active" {
			counts[key{lifecycle: "active", state: state, freshness: record.Freshness}]++
		}
	}
	for _, state := range []string{"complete", "incomplete", "unknown"} {
		for _, lifecycle := range []string{"active", "historical", "unknown"} {
			p.metric("artigate_low_container_discovery_records_by_lifecycle", "gauge",
				"Durable discovery observations by reference lifecycle and coverage state.",
				float64(counts[key{lifecycle: lifecycle, state: state}]), "lifecycle", lifecycle, "state", state)
		}
		for _, freshness := range []string{"fresh", "stale", "unknown"} {
			p.metric("artigate_low_container_discovery_current_records", "gauge",
				"Current tag and explicitly pinned digest observations by coverage and freshness; stale after 24 hours.",
				float64(counts[key{lifecycle: "active", state: state, freshness: freshness}]), "state", state, "freshness", freshness)
		}
	}
}

func writeContainerDiscoveryMetrics(p *promWriter, records []ContainerDiscoveryRecord) {
	counts, artifacts, issues := map[string]int{}, map[string]int{}, map[string]int{}
	var checked, successful, dropped int64
	for _, record := range records {
		status := record.Discovery
		state := "unknown"
		if status != nil {
			state = normalizedContainerDiscoveryState(status.State)
			artifacts[state] += status.Artifacts
			checked = max(checked, containerDiscoveryTimestamp(status.CheckedAt))
			successful = max(successful, containerDiscoveryTimestamp(status.LastSuccessAt))
			dropped += int64(status.IssuesDropped)
			for _, issue := range status.Issues {
				issues[issue.Code]++
			}
		}
		counts[state]++
	}
	for _, state := range []string{"complete", "incomplete", "unknown"} {
		p.metric("artigate_low_container_discovery_records", "gauge",
			"Latest durable attachment discovery observations by state.", float64(counts[state]), "state", state)
		p.metric("artigate_low_container_discovery_artifacts", "gauge",
			"Artifact observations in the latest discovery records; shared artifacts may be counted more than once.", float64(artifacts[state]), "state", state)
	}
	writeContainerDiscoveryIssueMetrics(p, issues)
	p.metric("artigate_low_container_discovery_issues_dropped", "gauge",
		"Additional issues omitted from bounded discovery reports.", float64(dropped))
	p.metric("artigate_low_container_discovery_last_check_timestamp_seconds", "gauge",
		"Unix time of the newest persisted attachment discovery attempt, or zero when unknown.", float64(checked))
	p.metric("artigate_low_container_discovery_last_success_timestamp_seconds", "gauge",
		"Unix time of the newest complete attachment discovery, or zero when unknown.", float64(successful))
}

func writeContainerDiscoveryIssueMetrics(p *promWriter, issues map[string]int) {
	codes := []string{"referrers_api", "referrers_fallback", "legacy_fetch", "artifact_fetch", "artifact_invalid", "discovery_limit", "cancelled"}
	sort.Strings(codes)
	for _, code := range codes {
		p.metric("artigate_low_container_discovery_issues", "gauge",
			"Issues in the latest durable discovery observations, by fixed reason code.", float64(issues[code]), "code", code)
	}
}

func normalizedContainerDiscoveryState(state string) string {
	if state == "complete" || state == "incomplete" {
		return state
	}
	return "unknown"
}

func containerDiscoveryTimestamp(value string) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return max(t.Unix(), 0)
}
