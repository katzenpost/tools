// main.go - Katzenpost mailproxy client registration cli tool
// Copyright (C) 2018  David Stainton.
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
	"os/user"
	"path"

	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/playground"
	"github.com/katzenpost/registration_client/mailproxy"
	"github.com/katzenpost/registration_client"
)

func main() {
	accountName := flag.String("name", "", "account name to register")
	providerName := flag.String("provider", playground.ProviderName, "provider to use")
	providerKey := flag.String("providerKey", playground.ProviderKeyPin, "provider to use")

	authority := flag.String("authority", playground.AuthorityAddr, "address of nonvoting pki")
	onionAuthority := flag.String("onionAuthority", playground.OnionAuthorityAddr, ".onion address of nonvoting pki")
	authorityKey := flag.String("authorityKey", playground.AuthorityPublicKey, "authority public key, base64 or hex")

	registrationAddr := flag.String("registrationAddress", playground.RegistrationAddr, "account registration address")
	onionRegistrationAddr := flag.String("onionRegistrationAddress", playground.OnionRegistrationAddr, "account registration address")

	registerWithOnion := flag.Bool("onion", false, "register using the Tor onion service")
	socksNet := flag.String("torSocksNet", "tcp", "tor SOCKS network (e.g. tcp or unix)")
	socksAddr := flag.String("torSocksAddr", "127.0.0.1:9150", "tor SOCKS address (e.g. 127.0.0.1:9050")
	dataDir := flag.String("dataDir", "", "mailproxy data directory, defaults to ~/.mailproxy")
	flag.Parse()

	if len(*accountName) == 0 {
		flag.Usage()
		return
	}

	// 1. ensure mailproxy data dir doesn't already exist
	mailproxyDir := ""
	if len(*dataDir) == 0 {
		usr, err := user.Current()
		if err != nil {
			panic("failure to retrieve current user information")
		}
		mailproxyDir = path.Join(usr.HomeDir, ".mailproxy")
	} else {
		mailproxyDir = *dataDir
	}
	if _, err := os.Stat(mailproxyDir); !os.IsNotExist(err) {
		panic(fmt.Sprintf("aborting registration, %s already exists", mailproxyDir))
	}
	if err := utils.MkDataDir(mailproxyDir); err != nil {
		panic(err)
	}

	// 2. generate mailproxy key material and configuration
	linkKey, identityKey, err := mailproxy.GenerateConfig(*accountName, *providerName, *providerKey, *authority, *onionAuthority, *authorityKey, mailproxyDir, *socksNet, *socksAddr, *registerWithOnion)
	if err != nil {
		panic(err)
	}

	// 3. perform registration with the mixnet Provider
	var options *client.Options = nil
	if *registerWithOnion {
		registrationAddr = onionRegistrationAddr
		options = &client.Options{
			Scheme:       "http",
			UseSocks:     true,
			SocksNetwork: *socksNet,
			SocksAddress: *socksAddr,
		}
	}
	c, err := client.New(*registrationAddr, options)
	if err != nil {
		panic(err)
	}
	err = c.RegisterAccountWithIdentityAndLinkKey(*accountName, linkKey, identityKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Successfully registered %s@%s\n", *accountName, *providerName)
	fmt.Printf("mailproxy -f %s\n", *dataDir+"/mailproxy.toml")
}
