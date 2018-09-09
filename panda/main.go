// main.go - Katzenpost PANDA cli tool
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
	"github.com/katzenpost/core/crypto/rand"
	pclient "github.com/katzenpost/panda/client"
	"github.com/katzenpost/panda/crypto"
)

const (
	pandaService = "panda"
)

func main() {
	var configFile string
	var sharedSecret string
	var message string
	var provider string
	var recipient string
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&sharedSecret, "secret", "", "the share secret")
	flag.StringVar(&provider, "provider", "", "the Provider of the PANDA server")
	flag.StringVar(&recipient, "recipient", "", "the recipient of the PANDA service")
	flag.StringVar(&message, "message", "", "the secret message")
	flag.Parse()

	if *genOnly {
		cfg, err := config.LoadFile(configFile, *genOnly)
		if err != nil {
			panic(err)
		}
		_, err = client.New(cfg)
		if err != nil {
			panic(err)
		}
		return
	}

	cfg, err := config.LoadFile(configFile, *genOnly)
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

	// do the PANDA protocol here
	blobSize := 10000
	panda := pclient.New(blobSize, session, c.GetLogger("katzenpost/PANDA"), recipient, provider)
	kx, err := crypto.NewKeyExchange(rand.Reader, panda, []byte(sharedSecret), []byte(message))
	if err != nil {
		panic(err)
	}
	reply, err := kx.Run()
	if err != nil {
		panic(err)
	}
	fmt.Printf("GOT REPLY: %s\n", string(reply))

	// shutdown the client
	c.Shutdown()
}
