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
	"os/signal"
	"syscall"

	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
)

const (
	messageTemplate string = "MIME-Version: 1.0\nDate: %v\nSubject: %v\nFrom: %v\nTo: %v\nContent-Type: text/plain; charset=\"UTF-8\"\n\n%v"
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

	// Setup an event sink.
	cfg.Proxy.EventSink = make(chan event.Event)
	go func() {
		for {
			select {
			case ievent := <-cfg.Proxy.EventSink:
				fmt.Printf("Received EVENT: %s\n", ievent)
				switch event := ievent.(type) {
				case *event.ConnectionStatusEvent:
					fmt.Println("ConnectionStatusEvent")
				case *event.MessageSentEvent:
					fmt.Println("MessageSentEvent")
				case *event.MessageReceivedEvent:
					fmt.Println("MessageReceivedEvent")
				case *event.KaetzchenReplyEvent:
					fmt.Printf("KaetzchenReplyEvent payload %s", string(event.Payload))
				}
			}
		}
	}()

	// Setup the signal handling.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	// Start up the proxy.
	fmt.Printf("Starting pong...\n")
	proxy, err := mailproxy.New(cfg)
	if err != nil {
		if err == mailproxy.ErrGenerateOnly {
			os.Exit(0)
		}
		fmt.Printf("Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	defer proxy.Shutdown()

	// Halt the proxy gracefully on SIGINT/SIGTERM, and scan RecipientDir on SIGHUP.
	go func() {
		for {
			switch <-ch {
			default:
				proxy.Shutdown()
				close(cfg.Proxy.EventSink)
				return
			}
		}
	}()

	// Wait for the proxy to explode or be terminated.
	proxy.Wait()
}
