// main.go - Katzenpost wallet client for Zcash
// Copyright (C) 2017  David Stainton
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
	"os"

	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	"github.com/ugorji/go/codec"
)

const (
	zcashSendVersion = 0

	WalletCfgEnvVar = "WALLETCFG"

	SenderID   = "anonymous"
	ProviderID = "provider2"

	ServiceID       = "zcash"
	ServiceProvider = "zcash1"
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
		_, err := config.LoadFile(os.Getenv(WalletCfgEnvVar), *genOnly)
		if err != nil {
			panic(err)
		}
		return
	}

	if len(os.Args) != 2 {
		panic("must specify tx hex blob as the only argument")
	}
	hexTx := os.Args[1]

	cfg, err := config.LoadFile(os.Getenv(WalletCfgEnvVar), *genOnly)
	if err != nil {
		panic(err)
	}

	cfg.Proxy.EventSink = make(chan event.Event)

	proxy, err := mailproxy.New(cfg)
	if err != nil {
		panic(err)
	}

	// block until we receive an event... like connected
	fmt.Printf("even sink %v\n", cfg.Proxy.EventSink)
	<-cfg.Proxy.EventSink

	senderAccount := fmt.Sprintf("%s@%s", SenderID, ProviderID)
	if proxy.IsConnected(senderAccount) {
		fmt.Printf("%v connected\n", senderAccount)
	} else {
		fmt.Printf("%v NOT connected\n", senderAccount)
	}

	var req = zcashSendRequest{
		Version: zcashSendVersion,
		Tx:      hexTx,
	}
	var out []byte
	enc := codec.NewEncoderBytes(&out, &jsonHandle)
	enc.Encode(req)

	fmt.Printf("sending tx blob of size %d\n", len(hexTx))
	msgId, err := proxy.SendKaetzchenRequest(senderAccount, ServiceID, ServiceProvider, out, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("submitted with message ID %x\n", msgId)

	event := <-cfg.Proxy.EventSink
	fmt.Printf("EVENT: %v %s", event, event.String())

	proxy.Shutdown()
}
