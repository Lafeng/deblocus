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

//
// This is an implementation of Diffie-Hellman Key Exchange algorithm.
// The algorithm is used to establish a shared key between two communication peers
// without sharing secrete information.
//
//
// Typical process:
//
// First, Alice and Bob should agree on which group to use. If you are not sure, choose group 14.
// GetGroup() will return the desired group by a given id.
// GetGroup(0) will return a default group, which is usually safe enough to use this group.
// It is totally safe to share the group's information.
//
// NOTE: The code below will skip error-checking part for the sake of simplicity.
//
// Here is the code on Alice's side:
//
//	// Get a group. Use the default one would be enough.
// 	g, _ := GetGroup(0)
//
// 	// Generate a private key from the group.
// 	// Use the default random number generator.
// 	priv, _ := g.GeneratePrivateKey(nil)
//
// 	// Get the public key from the private key.
// 	pub := priv.Bytes()
//
// 	// Send the public key to Bob.
// 	Send("Bob", pub)
//
// 	// Receive a slice of bytes from Bob, which contains Bob's public key
// 	b := Recv("Bob")
//
//	// Recover Bob's public key
// 	bobPubKey := NewPublicKey(b)
//
// 	// Compute the key
// 	k, _ := group.ComputeKey(bobPubKey, priv)
//
// 	// Get the key in the form of []byte
// 	key := k.Bytes()
//
// Similarly, here is the code on Bob's side:
//
//	// Get a group. Use the default one would be enough.
// 	g, _ := GetGroup(0)
//
// 	// Generate a private key from the group.
// 	// Use the default random number generator.
// 	priv, _ := g.GeneratePrivateKey(nil)
//
// 	// Get the public key from the private key.
// 	pub := priv.Bytes()
//
// 	// Receive a slice of bytes from Alice, which contains Alice's public key
// 	a := Recv("Alice")
//
// 	// Send the public key to Alice.
// 	Send("Alice", pub)
//
//	// Recover Alice's public key
// 	alicePubKey := NewPublicKey(a)
//
// 	// Compute the key
// 	k, _ := group.ComputeKey(alicePubKey, priv)
//
// 	// Get the key in the form of []byte
// 	key := k.Bytes()
//
// To this point, the variables ''key'' on both Alice and Bob side are same.
// It could be used as the secrete key for the later communication.
//
package dhkx
