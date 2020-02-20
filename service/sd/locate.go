package main

import (
	"context"
	"encoding/hex"
	"fmt"
)

var locateUsage = "locate name service protocol"

func locate(args []string) {
	if len(args) < 3 {
		exitUsage(locateUsage)
	}

	name, service, protocol := args[0], args[1], args[2]
	addrs, txts, err := sd.Locate(context.Background(), name, service, protocol)
	if err != nil {
		exitError(err)
	}

	for _, t := range txts {
		fmt.Println(hex.Dump([]byte(t)))
	}

	for _, a := range addrs {
		fmt.Println(a)
	}
}
