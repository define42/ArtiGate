package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func runContainers(args []string) {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: artigate containers check --root HIGH_ROOT [--repository registry/repo] [--repair] [--json]")
		os.Exit(2)
	}
	os.Exit(runContainersCheck(args[1:], os.Stdout, os.Stderr))
}

func runContainersCheck(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("containers check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := containerIntegrityOptions{}
	flags.StringVar(&options.Root, "root", "", "existing high-side storage root (required)")
	flags.StringVar(&options.Repository, "repository", "", "check only this registry/repository")
	flags.BoolVar(&options.Repair, "repair", false, "atomically rebuild derived artifact indexes after complete validation")
	asJSON := flags.Bool("json", false, "write the integrity report as JSON")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: artigate containers check --root HIGH_ROOT [--repository registry/repo] [--repair] [--json]")
		fmt.Fprintln(stderr, "Offline command: stop the high side before checking or repairing. The default is report-only.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if options.Root == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := checkContainerIntegrity(ctx, options)
	if err != nil {
		fmt.Fprintln(stderr, "containers check:", err)
		return 1
	}
	if err := writeContainerIntegrityReport(stdout, report, *asJSON); err != nil {
		fmt.Fprintln(stderr, "containers check:", err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func writeContainerIntegrityReport(output io.Writer, report containerIntegrityReport, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	for _, repository := range report.Repositories {
		for _, issue := range repository.Issues {
			if _, err := fmt.Fprintf(output, "%s: %s: %s\n", repository.Name, issue.Code, issue.Detail); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(output, "Checked %d repositories and %d blobs; repaired %d indexes; ok=%t\n",
		len(report.Repositories), report.BlobsChecked, report.Repaired, report.OK)
	return err
}
