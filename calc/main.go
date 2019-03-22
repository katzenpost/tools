// main.go - Katzenpost calculator
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
	"fmt"
	"time"

	"github.com/katzenpost/core/crypto/rand"
)

func main() {

	lambda := float64(0.001)
	max := uint64(90000)

	rng := rand.NewMath()

	for i := 0; i < 40; i++ {
		wakeMsec := uint64(rand.Exp(rng, lambda))
		switch {
		case wakeMsec > max:
			wakeMsec = max
		default:
		}
		wakeInterval := time.Duration(wakeMsec) * time.Millisecond
		fmt.Printf("duration %s\n", wakeInterval.String())
	}
}
