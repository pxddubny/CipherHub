package main

import (
	"fmt"
	"os"

	"github.com/pxddubny/CipherHub/internal/app"
	"github.com/pxddubny/CipherHub/internal/config"
)

// func generateSync() ([8]byte, error) {
//     var sync [8]byte

//     _, err := rand.Read(sync[:])
//     if err != nil {
//         return sync, err
//     }

//     return sync, nil
// }

func main() {
	mac, err := run(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if mac != nil {
		fmt.Printf("MAC: 0x%08X\n", *mac)
	}
}

func run(args []string) (*uint32, error) {
	cfg, err := config.Parse(args)
	if err != nil {
		return nil, err
	}

	return app.Run(cfg)
}
