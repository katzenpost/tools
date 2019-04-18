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
	"bytes"
	"flag"
	"fmt"

	"github.com/katzenpost/channels"
	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	memspoolclient "github.com/katzenpost/memspool/client"
)

const (
	spoolService = "spool"
)

func main() {
	var aliceConfigFile string
	var bobConfigFile string
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.StringVar(&aliceConfigFile, "a", "", "configuration file")
	flag.StringVar(&bobConfigFile, "b", "", "configuration file")
	flag.Parse()

	// alice
	aliceCfg, err := config.LoadFile(aliceConfigFile, *genOnly)
	if err != nil {
		panic(err)
	}
	aliceClient, err := client.New(aliceCfg)
	if err != nil {
		panic(err)
	}
	aliceSession, err := aliceClient.NewSession()
	if err != nil {
		panic(err)
	}

	// bob
	bobCfg, err := config.LoadFile(bobConfigFile, *genOnly)
	if err != nil {
		panic(err)
	}
	bobClient, err := client.New(bobCfg)
	if err != nil {
		panic(err)
	}
	bobSession, err := bobClient.NewSession()
	if err != nil {
		panic(err)
	}

	// get receiver and provider of memspool service
	serviceDesc, err := aliceSession.GetService("spool")
	if err != nil {
		panic(err)
	}

	// setup comm channels
	aliceSpoolService := memspoolclient.New(aliceSession)
	aliceSpoolChan, err := channels.NewUnreliableSpoolChannel(serviceDesc.Name, serviceDesc.Provider, aliceSpoolService)
	if err != nil {
		panic(err)
	}
	bobSpoolService := memspoolclient.New(bobSession)
	bobSpoolChan, err := channels.NewUnreliableSpoolChannel(serviceDesc.Name, serviceDesc.Provider, bobSpoolService)
	if err != nil {
		panic(err)
	}

	aliceWriterChanDesc := aliceSpoolChan.GetSpoolWriter()
	bobWriterChanDesc := bobSpoolChan.GetSpoolWriter()
	bobSpoolChan.WithRemoteWriter(aliceWriterChanDesc)
	aliceSpoolChan.WithRemoteWriter(bobWriterChanDesc)

	// signal double ratchets
	ratchetChanAlice, err := channels.NewUnreliableDoubleRatchetChannel(aliceSpoolChan)
	if err != nil {
		panic(err)
	}
	descAlice, err := ratchetChanAlice.KeyExchange()
	if err != nil {
		panic(err)
	}

	ratchetChanBob, err := channels.NewUnreliableDoubleRatchetChannel(bobSpoolChan)
	if err != nil {
		panic(err)
	}
	descBob, err := ratchetChanBob.KeyExchange()
	if err != nil {
		panic(err)
	}

	err = ratchetChanBob.ProcessKeyExchange(descAlice)
	if err != nil {
		panic(err)
	}
	err = ratchetChanAlice.ProcessKeyExchange(descBob)
	if err != nil {
		panic(err)
	}

	msg3 := []byte("write something cool here in place of this message")
	err = ratchetChanAlice.Write(msg3)
	if err != nil {
		panic(err)
	}
	msg3Read, err := ratchetChanBob.Read()
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(msg3, msg3Read) {
		panic("wtf messages not equal")
	}
	msg4 := []byte("different message here written")
	err = ratchetChanAlice.Write(msg4)
	if err != nil {
		panic(err)
	}
	msg4Read, err := ratchetChanBob.Read()
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(msg4, msg4Read) {
		panic("wtf messages not equal")
	}

	fmt.Println("Done. Shutting down.")
	aliceClient.Shutdown()
	bobClient.Shutdown()
}
