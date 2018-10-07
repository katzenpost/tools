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
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/rand"
	pclient "github.com/katzenpost/panda/client"
	"github.com/katzenpost/panda/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	pandaService = "panda"
)

func main() {
	var configFile string
	var shareFile string
	var recipient string
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&recipient, "panda", "", "the recipient of the PANDA service, in the form: user@provider")
	flag.StringVar(&shareFile, "file", "", "the file to share")
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

	// parse recipient from commandline arg
	fields := strings.Split(recipient, "@")
	if len(fields) != 2 {
		flag.Usage()
		return
	}
	user := fields[0]
	provider := fields[1]

	// read file to share
	message, err := ioutil.ReadFile(shareFile)
	if err != nil {
		panic(err)
	}

	// prompt for passphrase
	fmt.Printf("passphrase>> ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	// load config
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
	panda := pclient.New(blobSize, session, c.GetLogger("katzenpost/PANDA"), user, provider)
	kx, err := crypto.NewKeyExchange(rand.Reader, panda, []byte(passphrase), message)
	if err != nil {
		panic(err)
	}
	reply, err := kx.Run()
	if err != nil {
		panic(err)
	}

	// write the file to disk
	perm := os.FileMode(0400)
	err = ioutil.WriteFile("output", reply, perm)
	if err != nil {
		panic(err)
	}

	// shutdown the client
	c.Shutdown()
}
