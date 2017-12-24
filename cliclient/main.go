// client.go - Katzenpost demotools minclient.
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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	npki "github.com/katzenpost/authority/nonvoting/client"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient/block"
)

var surbKeys = make(map[[constants.SURBIDLength]byte][]byte)

type FakeUserKeyDiscovery struct{}

func (d *FakeUserKeyDiscovery) Get(identity string) (*ecdh.PublicKey, error) {
	fmt.Println("FakeUserKeyDiscovery Get")
	if identity == "alice@idefix" {
		bobsKey := new(ecdh.PublicKey)
		//bobsKey.FromString("")
		raw := [32]byte{}
		_, err := rand.Reader.Read(raw[:])
		if err != nil {
			return nil, err
		}
		bobsKey.FromBytes(raw[:])
		return bobsKey, nil
	}
	if identity == "bob@ramix" {
		bobsKey := new(ecdh.PublicKey)
		//bobsKey.FromString("")
		raw := [32]byte{}
		_, err := rand.Reader.Read(raw[:])
		if err != nil {
			return nil, err
		}
		bobsKey.FromBytes(raw[:])
		return bobsKey, nil
	}
	return nil, fmt.Errorf("failure FakeUserKeyDiscovery: user %s not found", identity)
}

type PrintMessageConsumer struct{}

func (c *PrintMessageConsumer) ReceivedMessage(senderPubKey *ecdh.PublicKey, message []byte) {
	fmt.Printf("received message from %x\n", *senderPubKey)
	fmt.Printf("message: %s\n", string(message))
}

func (c *PrintMessageConsumer) ReceivedACK(messageID *[block.MessageIDLength]byte) {
	fmt.Printf("received ACK for message ID: %x\n", *messageID)
}

func newLog(cfg *Logging) (*log.Backend, error) {
	return log.New(cfg.File, cfg.Level, cfg.Disable)
}

type FakeStorage struct{}

func (s *FakeStorage) GetIngressBlocks(*[block.MessageIDLength]byte) ([][]byte, error) {
	return nil, nil
}

func (s *FakeStorage) PutIngressBlock(*[block.MessageIDLength]byte, []byte) error {
	return nil
}

func (s *FakeStorage) PutEgressBlock(*[block.MessageIDLength]byte, *client.EgressBlock) error {
	return nil
}

func (s *FakeStorage) AddSURBKeys(*[constants.SURBIDLength]byte, *client.EgressBlock) error {
	return nil
}

func (s *FakeStorage) RemoveSURBKey(*[constants.SURBIDLength]byte) error {
	return nil
}

func newPKIClient(cfg *Nonvoting, clientLog *log.Backend) (cpki.Client, error) {
	pubkey, err := cfg.getPublicKey()
	if err != nil {
		return nil, err
	}
	pkiCfg := npki.Config{
		LogBackend: clientLog,
		Address:    cfg.Address,
		PublicKey:  pubkey,
	}
	return npki.New(&pkiCfg)
}

func main() {
	cfgFile := flag.String("f", "client.toml", "Path to the client config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	message := flag.String("m", "hello, from Alice", "Message to send.")
	flag.Parse()

	if *genOnly {
		key, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to to generate the key: %v\n", err)
			os.Exit(-1)
		}
		fmt.Printf("Private key: %v\n", hex.EncodeToString(key.Bytes()))
		fmt.Printf("Public key: %v\n", key.PublicKey().String())
		os.Exit(0)
	}

	cfg, err := LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	clientLog, err := newLog(cfg.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client log: %v\n", err)
		os.Exit(-1)
	}

	pkiClient, err := newPKIClient(cfg.PKI.Nonvoting, clientLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create PKI client: %v\n", err)
		os.Exit(-1)
	}
	clientCfg := client.Config{
		LogBackend: clientLog,
		PKIClient:  pkiClient,
		Name:       "cliclient",
	}
	mixClient, err := client.New(&clientCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "1Failed to create client: %s\n", err)
		os.Exit(-1)
	}

	linkPrivKey, err := ECDHPrivateKeyFromString(cfg.Account.LinkPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load key: %v\n", err)
		os.Exit(-1)
	}
	identityPrivKey, err := ECDHPrivateKeyFromString(cfg.Account.IdentityPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load key: %v\n", err)
		os.Exit(-1)
	}

	sessionCfg := client.SessionConfig{
		User:              cfg.Account.Name,
		Provider:          cfg.Account.Provider,
		LinkPrivKey:       linkPrivKey,
		IdentityPrivKey:   identityPrivKey,
		MessageConsumer:   new(PrintMessageConsumer),
		Storage:           new(FakeStorage),
		UserKeyDiscovery:  new(FakeUserKeyDiscovery),
		PeriodicSendDelay: 10 * time.Second,
	}

	session, err := mixClient.NewSession(&sessionCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create new session: %v\n", err)
		os.Exit(-1)
	}

	fmt.Printf("session %v message %v\n", session, message)
	// err = session.SendUnreliable(cfg.Account.Name, cfg.Account.Provider, []byte(*message))
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to send message: %v\n", err)
	// 	os.Exit(-1)
	// }

	fmt.Printf("\ncontrol-C to quit\n")

	// Setup the signal handling.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
