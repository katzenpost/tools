// main.go - Katzenpost wallet client for Zcash
// Copyright (C) 2018  David Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/server_plugins/currency/common"
	"github.com/ugorji/go/codec"
)

const (
	zcashService = "zec"
	zcashTicker  = "ZEC"
)

var (
	jsonHandle codec.JsonHandle
)

type zcashSendRequest struct {
	Version int
	Tx      string
}

func main() {
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the server config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	hexBlob := flag.String("t", "", "Transaction hex blob to send.")
	flag.Parse()

	if *genOnly {
		_, err := config.LoadFile(*cfgFile, *genOnly)
		if err != nil {
			panic(err)
		}
		return
	}

	if *hexBlob == "" {
		panic("must specify tx hex blob")
	}

	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		panic(err)
	}

	// create a client and connect to the mixnet Provider
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	session, err := c.NewSession()
	if err != nil {
		panic(err)
	}

	// serialize our transaction inside a zcash kaetzpost request message
	req := common.NewRequest(zcashTicker, *hexBlob)
	zcashRequest := req.ToJson()

	// find a zcash proxy service
	zcashService, err := session.GetService(zcashService)
	if err != nil {
		panic(err)
	}

	// send the zcash transaction
	wantReply := true
	msgRef, err := session.SendKaetzchenQuery(zcashService.Name, zcashService.Provider, zcashRequest, wantReply)
	if err != nil {
		panic(err)
	}

	reply := session.WaitForReply(msgRef)
	fmt.Printf("reply: %s\n", reply)
	fmt.Println("Done. Shutting down.")
	c.Shutdown()
}
