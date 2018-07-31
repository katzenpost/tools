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
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
)

func main() {
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the server config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	// Load the configuration.
	fmt.Printf("Loading Configuration...\n")
	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}
	// create an event channel to receive events on
	cfg.Proxy.EventSink = make(chan event.Event)

	// Start up the proxy.
	fmt.Printf("Starting mailproxy...\n")
	proxy, err := mailproxy.New(cfg)
	if err != nil {
		if err == mailproxy.ErrGenerateOnly {
			os.Exit(0)
		}
		fmt.Printf("Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	shell := NewShell(proxy, cfg)
	shell.Run()
}
