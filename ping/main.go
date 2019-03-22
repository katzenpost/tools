// main.go - Katzenpost ping tool
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
)

const (
	pingService = "echo"
)

func main() {
	var configFile string
	var service string
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "", "service name")
	flag.Parse()

	if service == "" {
		panic("must specify service name with -s")
	}

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
	s, err := c.NewSession()
	if err != nil {
		panic(err)
	}

	serviceDesc, err := s.GetService(service)
	if err != nil {
		panic(err)
	}
	fmt.Println(serviceDesc.Name, serviceDesc.Provider)

	msgId, err := s.SendUnreliableQuery(serviceDesc.Name, serviceDesc.Provider, []byte("hello"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Awaiting reply for message ID: %x\n", *msgId)
	mesg := s.WaitForReply(msgId)
	fmt.Printf("reply: %s\n", mesg)
	fmt.Println("Done. Shutting down.")
	c.Shutdown()
}
