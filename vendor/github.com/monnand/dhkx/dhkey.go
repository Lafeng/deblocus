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
	"math/big"
)

type DHKey struct {
	x *big.Int
	y *big.Int

	group *DHGroup
}

func (self *DHKey) Bytes() []byte {
	if self.y == nil {
		return nil
	}
	if self.group != nil {
		// len = ceil(bitLen(y) / 8)
		blen := (self.group.p.BitLen() + 7) / 8
		ret := make([]byte, blen)
		copyWithLeftPad(ret, self.y.Bytes())
		return ret
	}
	return self.y.Bytes()
}

func (self *DHKey) String() string {
	if self.y == nil {
		return ""
	}
	return self.y.String()
}

func (self *DHKey) IsPrivateKey() bool {
	return self.x != nil
}

func NewPublicKey(s []byte) *DHKey {
	key := new(DHKey)
	key.y = new(big.Int).SetBytes(s)
	return key
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes as
// needed.
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}
