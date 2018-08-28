// main.go - Katzenpost client registration cli tool
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
	"github.com/katzenpost/core/crypto/ecdh"
	client "github.com/katzenpost/registration_client"
)

func main() {
	user := flag.String("u", "", "username (e.g. 'alice')")
	address := flag.String("a", "", "Network address (e.g. '127.0.0.1:45666'")
	linkKeyStr := flag.String("l", "", "Link public key in hex or base64")
	flag.Parse()

	if len(*user) == 0 ||
		len(*address) == 0 ||
		len(*linkKeyStr) == 0 {
		flag.Usage()
		return
	}

	c := client.New(*address, nil)
	linkKey := new(ecdh.PublicKey)
	linkKey.FromString(*linkKeyStr)
	err := c.RegisterAccountWithLinkKey(*user, linkKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("Success.")
}
