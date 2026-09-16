//go:build e2e

// The receiver runs inside an otherwise disconnected network namespace. Its
// sole bridge is a Unix socket whose host peer dials one fixed high-side port.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
)

func main() {
	os.Exit(run())
}

func run() int {
	listen := flag.String("listen", "", "high-side loopback address")
	socket := flag.String("socket", "", "Unix socket bridging only the high side")
	loopback := flag.Bool("loopback", false, "bring up the new namespace's loopback interface")
	flag.Parse()
	if *loopback {
		if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
			return failed(fmt.Errorf("bring up receiver loopback: %w: %s", err, out))
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return failed(err)
	}
	defer listener.Close()
	go serve(listener, *socket)
	if err := os.MkdirAll(os.Getenv("HOME"), 0o755); err != nil {
		return failed(err)
	}
	args := flag.Args()
	if len(args) == 0 {
		return failed(errors.New("missing receiver command"))
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		return failed(err)
	}
	return 0
}

func failed(err error) int {
	fmt.Fprintln(os.Stderr, "receiver:", err)
	return 1
}

func serve(listener net.Listener, socket string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			upstream, err := net.Dial("unix", socket)
			if err != nil {
				fmt.Fprintln(os.Stderr, "receiver bridge:", err)
				return
			}
			defer upstream.Close()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, conn)
				_ = upstream.(*net.UnixConn).CloseWrite()
				close(done)
			}()
			_, _ = io.Copy(conn, upstream)
			_ = conn.(*net.TCPConn).CloseWrite()
			<-done
		}()
	}
}
