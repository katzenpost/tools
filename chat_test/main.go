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
	chanAlice, err := channels.NewUnreliableNoiseChannel(serviceDesc.Name, serviceDesc.Provider, aliceSession)
	if err != nil {
		panic(err)
	}

	chanBob, err := channels.NewUnreliableNoiseChannel(serviceDesc.Name, serviceDesc.Provider, bobSession)
	if err != nil {
		panic(err)
	}

	chanAliceDescriptor := chanAlice.DescribeWriter()
	chanBobDescriptor := chanBob.DescribeWriter()
	err = chanBob.WithRemoteWriterDescriptor(chanAliceDescriptor)
	if err != nil {
		panic(err)
	}
	err = chanAlice.WithRemoteWriterDescriptor(chanBobDescriptor)
	if err != nil {
		panic(err)
	}

	// test the comm channels
	msg1 := []byte(`hello`)
	err = chanAlice.Write(msg1)
	if err != nil {
		panic(err)
	}
	msg1Read, err := chanBob.Read()
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(msg1, msg1Read) {
		panic("wtf messages not equal")
	}

	msg2 := []byte(`goodbye`)
	err = chanBob.Write(msg2)
	if err != nil {
		panic(err)
	}
	msg2Read, err := chanAlice.Read()
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(msg2, msg2Read) {
		panic("wtf messages not equal")
	}

	// signal double ratchets
	ratchetChanAlice, err := channels.NewUnreliableDoubleRatchetChannel(chanAlice)
	if err != nil {
		panic(err)
	}
	descAlice := ratchetChanAlice.GetDescriptor()
	ratchetChanBob, err := channels.NewUnreliableDoubleRatchetChannelWithRemoteDescriptor(chanBob, descAlice)
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
