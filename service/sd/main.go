package main

import (
	"fmt"
	"os"

	"tessier-ashpool.net/dns/service"
)

func exitError(msg interface{}) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func exitErrorf(f string, args ...interface{}) {
	exitError(fmt.Sprintf(f, args...))
}

func exitUsage(cmd string) {
	fmt.Fprintf(os.Stderr, "usage: %s ", os.Args[0])
	if cmd == "" {
		fmt.Fprintln(os.Stderr, "command:")
		for _, c := range []string{hostnameUsage, lookupUsage, addrUsage, hostUsage, browseUsage, locateUsage} {
			fmt.Fprintf(os.Stderr, "\t%s\n", c)
		}
	} else {
		fmt.Fprintln(os.Stderr, cmd)
	}
	os.Exit(2)
}

const hostnameUsage = "hostname"

var sd = service.DefaultServices

func main() {

	if len(os.Args) < 2 {
		exitUsage("")
	}

	switch os.Args[1] {
	case "lookup":
		lookup(os.Args[2:])

	case "addr":
		lookupAddr(os.Args[2:])

	case "host":
		lookupHost(os.Args[2:])

	case "browse":
		browse(os.Args[2:])

	case "locate":
		locate(os.Args[2:])

	case "hostname":
		hostname(os.Args[2:])

	default:
		exitUsage("")
	}
}

func hostname(args []string) {
	for _, host := range sd.Hostname() {
		fmt.Println(host)
	}
}
