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

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
)

const (
	pingService = "loop"
)

func main() {
	var configFile string
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.Parse()

	if *genOnly {
		_, err := config.LoadFile(configFile, *genOnly)
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
	err = c.NewSession()
	if err != nil {
		panic(err)
	}
	c.WaitForPKIDocument()
	serviceDesc, err := c.GetService(pingService)
	if err != nil {
		panic(err)
	}
	wantReply := true

	msgRef, err := c.SendKaetzchenQuery(serviceDesc.Name, serviceDesc.Provider, []byte("hello"), wantReply)
	if err != nil {
		panic(err)
	}
	c.WaitForReply(msgRef)
	//c.Wait()
}
