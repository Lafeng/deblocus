package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/Lafeng/deblocus/exception"
	"github.com/monnand/dhkx"
	"math/big"
	"strings"
)

var (
	NoSuchDHMethod  = exception.New(0, "No Such DH method")
	InvalidECCParam = exception.New(0, "Invalid ECC parameters")
)

// enum: DHE, ECDHE-P224,256,384,521
func NewDHKey(name string) (DHKE, error) {
	name = strings.ToUpper(name)
	if name == "DHE" {
		return GenerateDHEKey()
	}
	if strings.HasPrefix(name, "ECDHE-") {
		name = name[6:]
	}
	var curve elliptic.Curve
	switch name {
	case "P224":
		curve = elliptic.P224()
	case "P256":
		curve = elliptic.P256()
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		return nil, NoSuchDHMethod.Apply(name)
	}
	return GenerateECKey(curve)
}

type DHKE interface {
	ExportPubKey() []byte
	ComputeKey(bobPub []byte) ([]byte, error)
}

type ECKey struct {
	curve  elliptic.Curve
	priv   []byte   // rand k
	xQ, yQ *big.Int // point Q
}

// Q = curve.G * k
// Q => k is ECDLP
func GenerateECKey(curve elliptic.Curve) (*ECKey, error) {
	k, xq, yq, e := elliptic.GenerateKey(curve, rand.Reader)
	if e != nil {
		return nil, e
	}
	return &ECKey{
		curve: curve,
		priv:  k,
		xQ:    xq,
		yQ:    yq,
	}, nil
}

// send Alice public key to Bob.
func (k *ECKey) ExportPubKey() []byte {
	return elliptic.Marshal(k.curve, k.xQ, k.yQ)
}

// Q' = curve.G * k'
// K(x,y) = Q' * k = G * k' * k
func (k *ECKey) ComputeKey(bobPub []byte) ([]byte, error) {
	curve := k.curve
	bobX, bobY := elliptic.Unmarshal(curve, bobPub)
	if bobX == nil || bobY == nil {
		// the point is not on the curve
		return nil, InvalidECCParam
	}
	xk, _ := curve.ScalarMult(bobX, bobY, k.priv)
	return xk.Bytes(), nil
}

const (
	_DH_GROUP_ID = 14 // 2048bits
)

// classical Diffie–Hellman–Merkle key exchange
type DHEKey struct {
	priv *dhkx.DHKey
	pub  []byte
}

func GenerateDHEKey() (k *DHEKey, err error) {
	// Get a group. Use the default one would be enough.
	g, _ := dhkx.GetGroup(_DH_GROUP_ID)
	k = new(DHEKey)
	// Generate a private key from the group.
	// Use the default random number generator.
	k.priv, err = g.GeneratePrivateKey(nil)
	if k.priv != nil {
		// Get the public key from the private key.
		k.pub = k.priv.Bytes()
	}
	return k, err
}

func (d *DHEKey) ExportPubKey() []byte {
	return d.pub
}

func (d *DHEKey) ComputeKey(pub []byte) ([]byte, error) {
	g, _ := dhkx.GetGroup(_DH_GROUP_ID)
	// Recover Bob's public key
	opubkey := dhkx.NewPublicKey(pub)
	// Compute the key
	k, e := g.ComputeKey(opubkey, d.priv)
	if e == nil {
		// Get the key in the form of []byte
		return k.Bytes(), nil
	}
	return nil, e
}
