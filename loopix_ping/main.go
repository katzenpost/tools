// main.go - Katzenpost ping tool
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

	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	"github.com/ugorji/go/codec"
)

const (
	CfgEnvVar       = "KATZENPOSTCFG"
	SenderAccountId = "anonymous@provider2"
)

var (
	jsonHandle codec.JsonHandle
)

type ServiceId struct {
	Name     string
	Provider string
}

func findServices(cfg *config.Config, proxy *mailproxy.Proxy, accountId string, serviceCapability string) []ServiceId {
	accountMap := cfg.AccountMap()
	account := accountMap[accountId]
	providers, err := proxy.ListProviders(account.Authority)
	if err != nil {
		panic(err)
	}

	services := []ServiceId{}
	for _, provider := range providers {
		for cap, _ := range provider.Kaetzchen {
			if cap == serviceCapability {
				serviceId := ServiceId{
					Name:     provider.Kaetzchen[cap]["endpoint"].(string),
					Provider: provider.Name,
				}
				services = append(services, serviceId)
			}
		}
	}
	return services
}

func main() {
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	flag.Parse()

	if *genOnly {
		_, err := config.LoadFile(os.Getenv(CfgEnvVar), *genOnly)
		if err != nil {
			panic(err)
		}
		return
	}
	cfg, err := config.LoadFile(os.Getenv(CfgEnvVar), *genOnly)
	if err != nil {
		panic(err)
	}

	cfg.Proxy.EventSink = make(chan event.Event)

	proxy, err := mailproxy.New(cfg)
	if err != nil {
		panic(err)
	}

	emptyPayload := []byte{}

	// block until we receive an event... like connected
	for {
		select {
		case mailproxyEvent := <-cfg.Proxy.EventSink:
			switch t := mailproxyEvent.(type) {
			case *event.ConnectionStatusEvent:
				fmt.Println("ConnectionStatusEvent")
				if t.IsConnected {
					services := findServices(cfg, proxy, SenderAccountId, "loop")
					for _, service := range services {
						fmt.Printf("SERVICE %s @ %s\n", service.Name, service.Provider)
						_, err = proxy.SendKaetzchenRequest(SenderAccountId, service.Name, service.Provider, emptyPayload, true)
						if err != nil {
							panic(err)
						}
					}
				} else {
					proxy.Shutdown()
					os.Exit(0)
				}
			case *event.MessageSentEvent:
				fmt.Println("MessageSentEvent")
				proxy.Shutdown()
				os.Exit(0)
			case *event.MessageReceivedEvent:
				fmt.Println("MessageReceivedEvent")
			case *event.KaetzchenReplyEvent:
				fmt.Println("KaetzchenReplyEvent")
			default:
				fmt.Println("an unhandled case!?")
				panic("wtf")
			}
		}
	}
	fmt.Println("finished!")
}
