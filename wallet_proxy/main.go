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
	"github.com/ugorji/go/codec"
)

const (
	zcashService     = "zec"
	zcashSendVersion = 0
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
	txBlob := flag.String("t", "", "tx hex blob to send")
	flag.Parse()

	if *genOnly {
		_, err := config.LoadFile(*cfgFile, *genOnly)
		if err != nil {
			panic(err)
		}
		return
	}

	if *txBlob == "" {
		panic("must specify tx hex blob")
	}

	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		panic(err)
	}

	// create a client and connect to the mixnet Provider
	_client, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	session, err := _client.NewSession()
	if err != nil {
		panic(err)
	}

	// serialize our transaction inside a zcash kaetzpost request message
	var req = zcashSendRequest{
		Version: zcashSendVersion,
		Tx:      *txBlob,
	}
	var zcashRequest []byte
	enc := codec.NewEncoderBytes(&zcashRequest, &jsonHandle)
	enc.Encode(req)

	// find a zcash proxy service
	zcashService, err := session.GetService(zcashService)
	if err != nil {
		panic(err)
	}

	// send the zcash transaction
	mesgRef, err := session.SendUnreliable(zcashService.Name, zcashService.Provider, zcashRequest)
	if err != nil {
		panic(err)
	}
	reply := session.WaitForReply(mesgRef)
	fmt.Printf("reply: %s", reply)
}
