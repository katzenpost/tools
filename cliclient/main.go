// client.go - Katzenpost demotools cliclient main.
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
	"log"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
)

func main() {
	provider0Key := new(eddsa.PublicKey)
	provider0Key.FromBytes([]byte("blah blah key")) // XXX

	linkPrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		log.Fatalf("failed to create a link key: %s", err)
	}
	identityPrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		log.Fatalf("failed to create an identity key: %s", err)
	}
	storagePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		log.Fatalf("failed to create a storage key: %s", err)
	}

	recipientPublicKey := new(ecdh.PublicKey)
	recipientPublicKey.FromBytes([]byte("blah blah key")) // XXX

	cfg := &config.Config{
		Proxy: &config.Proxy{
			DataDir: "/tmp/123",
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Management: &config.Management{
			Enable: false,
			Path:   "",
		},
		UpstreamProxy: nil,
		Debug: &config.Debug{
			ReceiveTimeout:               600,
			BounceQueueLifetime:          432000,
			PollingInterval:              30,
			RetransmitSlack:              300,
			CaseSensitiveUserIdentifiers: false,
			GenerateOnly:                 false,
		},
		NonvotingAuthority: map[string]*config.NonvotingAuthority{
			"provider0": &config.NonvotingAuthority{
				Address:   "", // XXX
				PublicKey: provider0Key,
			},
		},
		Account: []*config.Account{
			&config.Account{
				User:           "alice",
				Provider:       "provider0",
				ProviderKeyPin: provider0Key,
				Authority:      "authority0",
				LinkKey:        linkPrivateKey,
				IdentityKey:    identityPrivateKey,
				StorageKey:     storagePrivateKey,
			},
		},
		Recipients: map[string]*ecdh.PublicKey{
			"alice": recipientPublicKey,
		},
	}
	proxy, err := mailproxy.New(cfg)
	if err != nil {
		log.Fatalf("failed to create a mailproxy instance: %s", err)
	}
	err = proxy.SendMessage("senderid", "recipientid", []byte("hello world"))
	if err != nil {
		log.Fatalf("failed to send a message: %s", err)
	}
}
