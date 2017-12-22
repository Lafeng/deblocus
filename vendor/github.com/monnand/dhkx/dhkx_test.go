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
	"fmt"
	"math/big"
	"testing"
)

type peer struct {
	priv  *DHKey
	group *DHGroup
	pub   *DHKey
}

func newPeer(g *DHGroup) *peer {
	ret := new(peer)
	ret.priv, _ = g.GeneratePrivateKey(nil)
	ret.group = g
	return ret
}

func (self *peer) getPubKey() []byte {
	return self.priv.Bytes()
}

func (self *peer) recvPeerPubKey(pub []byte) {
	pubKey := NewPublicKey(pub)
	self.pub = pubKey
}

func (self *peer) getKey() []byte {
	k, err := self.group.ComputeKey(self.pub, self.priv)
	if err != nil {
		return nil
	}
	return k.Bytes()
}

func exchangeKey(p1, p2 *peer) error {
	pub1 := p1.getPubKey()
	pub2 := p2.getPubKey()

	p1.recvPeerPubKey(pub2)
	p2.recvPeerPubKey(pub1)

	key1 := p1.getKey()
	key2 := p2.getKey()

	if key1 == nil {
		return fmt.Errorf("p1 has nil key")
	}
	if key2 == nil {
		return fmt.Errorf("p2 has nil key")
	}

	for i, k := range key1 {
		if key2[i] != k {
			return fmt.Errorf("%vth byte does not same")
		}
	}
	return nil
}

func TestKeyExchange(t *testing.T) {
	group, _ := GetGroup(14)
	p1 := newPeer(group)
	p2 := newPeer(group)

	err := exchangeKey(p1, p2)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestCustomGroupKeyExchange(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
	g := new(big.Int).SetInt64(2)
	group := CreateGroup(p, g)
	p1 := newPeer(group)
	p2 := newPeer(group)

	err := exchangeKey(p1, p2)
	if err != nil {
		t.Errorf("%v", err)
	}
}
