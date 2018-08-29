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
	"fmt"
	"os"
	"os/user"
	"path"

	"github.com/katzenpost/core/utils"
	client "github.com/katzenpost/registration_client"
	"github.com/katzenpost/registration_client/mailproxy"
)

func main() {
	if len(os.Args) != 2 {
		panic("Must specify the username as the only commandline argument.")
	}

	accountName := os.Args[1]

	// 1. ensure ~/.mailproxy config directory doesn't already exist
	usr, err := user.Current()
	if err != nil {
		panic("failure to retrieve current user information")
	}
	mailproxyDir := path.Join(usr.HomeDir, ".mailproxy")
	if _, err := os.Stat(mailproxyDir); !os.IsNotExist(err) {
		panic("aborting registration, ~/.mailproxy already exists")
	}
	if err := utils.MkDataDir(mailproxyDir); err != nil {
		panic(err)
	}

	// 2. generate mailproxy key material and configuration
	linkKey, identityKey, err := mailproxy.GenerateConfig(accountName, mailproxyDir)
	if err != nil {
		panic(err)
	}

	// 3. perform registration with the mixnet Provider
	c := client.New(mailproxy.RegistrationAddr, nil)
	err = c.RegisterAccountWithIdentityAndLinkKey(accountName, linkKey, identityKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("Success.")
}
