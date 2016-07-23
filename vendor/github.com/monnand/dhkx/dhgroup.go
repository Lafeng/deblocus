/*
 * Copyright 2012 Nan Deng
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package dhkx

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type DHGroup struct {
	p *big.Int
	g *big.Int
}

func (self *DHGroup) GeneratePrivateKey(randReader io.Reader) (key *DHKey, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	// x should be in (0, p).
	// alternative approach:
	// x, err := big.Add(rand.Int(randReader, big.Sub(p, big.NewInt(1))), big.NewInt(1))
	//
	// However, since x is highly unlikely to be zero if p is big enough,
	// we would rather use an iterative approach below,
	// which is more efficient in terms of exptected running time.
	x, err := rand.Int(randReader, self.p)
	if err != nil {
		return
	}

	zero := big.NewInt(0)
	for x.Cmp(zero) == 0 {
		x, err = rand.Int(randReader, self.p)
		if err != nil {
			return
		}
	}
	key = new(DHKey)
	key.x = x

	// y = g ^ x mod p
	key.y = new(big.Int).Exp(self.g, x, self.p)
	key.group = self
	return
}

// This function fetches a DHGroup by its ID as defined in either RFC 2409 or
// RFC 3526.
//
// If you are unsure what to use use group ID 0 for a sensible default value
func GetGroup(groupID int) (group *DHGroup, err error) {
	if groupID <= 0 {
		groupID = 14
	}
	switch groupID {
	case 1:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case 2:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case 14:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	default:
		group = nil
		err = errors.New("DH: Unknown group")
	}
	return
}

// This function enables users to create their own custom DHGroup.
// Most users will not however want to use this function, and should prefer
// the use of GetGroup which supplies DHGroups defined in RFCs 2409 and 3526
//
// WARNING! You should only use this if you know what you are doing. The
// behavior of the group returned by this function is not defined if prime is
// not in fact prime.
func CreateGroup(prime, generator *big.Int) (group *DHGroup) {
	group = &DHGroup{
		g: generator,
		p: prime,
	}
	return
}

func (self *DHGroup) ComputeKey(pubkey *DHKey, privkey *DHKey) (key *DHKey, err error) {
	if self.p == nil {
		err = errors.New("DH: invalid group")
		return
	}
	if pubkey.y == nil {
		err = errors.New("DH: invalid public key")
		return
	}
	if pubkey.y.Sign() <= 0 || pubkey.y.Cmp(self.p) >= 0 {
		err = errors.New("DH parameter out of bounds")
		return
	}
	if privkey.x == nil {
		err = errors.New("DH: invalid private key")
		return
	}
	k := new(big.Int).Exp(pubkey.y, privkey.x, self.p)
	key = new(DHKey)
	key.y = k
	key.group = self
	return
}
