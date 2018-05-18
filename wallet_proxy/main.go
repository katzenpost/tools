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
	"os"

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/ugorji/go/codec"
)

const (
	zcashService     = "zcash"
	zcashSendVersion = 0
	walletCfgEnvVar  = "WALLETCFG"
)

var (
	jsonHandle codec.JsonHandle
)

type zcashSendRequest struct {
	Version int
	Tx      string
}

func main() {
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.Parse()

	if *genOnly {
		_, err := config.LoadFile(os.Getenv(walletCfgEnvVar), *genOnly)
		if err != nil {
			panic(err)
		}
		return
	}

	if len(os.Args) != 2 {
		panic("must specify tx hex blob as the only argument")
	}

	cfg, err := config.LoadFile(os.Getenv(walletCfgEnvVar), *genOnly)
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
	hexTx := os.Args[1]
	var req = zcashSendRequest{
		Version: zcashSendVersion,
		Tx:      hexTx,
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
	err = session.SendUnreliable(zcashService.Name, zcashService.Provider, zcashRequest)
	if err != nil {
		panic(err)
	}
}
