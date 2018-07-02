package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"strconv"

	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
)

var watchFdInstallPids string

func init() {
	flag.StringVar(&watchFdInstallPids, "monitor-fdinstall-pids", "", "a comma-separated list of pids that need to be monitored for fdinstall events")
	flag.Parse()
}

func main() {
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(1)
	}

	t, err := tracer.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	t.Start()
	for _, p := range strings.Split(watchFdInstallPids, ",") {
		if p == "" {
			continue
		}
		pid, err := strconv.ParseUint(p, 10, 32)
		if err != nil {

			fmt.Fprintf(os.Stderr, "Invalid pid: %v\n", err)

			os.Exit(1)
		}
		fmt.Printf("Monitor fdinstall events for pid %d\n", pid)
		t.AddFdInstallWatcher(uint32(pid))
	}

	defer t.Close()
	fmt.Printf("Ready\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	for {
		select {
		case e := <-t.Events():
			fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n",
				e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS)
		case <-sig:
			return
		}
	}
}
