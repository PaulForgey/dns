package main

import (
	"context"
	"fmt"
)

const locateUsage = "locate name service protocol"

func locate(args []string) {
	if len(args) < 3 {
		exitUsage(locateUsage)
	}

	name, service, protocol := args[0], args[1], args[2]
	addrs, txts, err := sd.Locate(context.Background(), name, service, protocol)
	if err != nil {
		exitError(err)
	}

	for k, v := range txts {
		fmt.Printf("%s=%q\n", k, v)
	}

	for _, a := range addrs {
		fmt.Println(a)
	}
}
