package depot

import (
	"crypto"
	"crypto/x509"
	"math/big"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte) ([]*x509.Certificate, *crypto.PrivateKey, error)
	Put(name string, crt *x509.Certificate) error
	Serial() (*big.Int, error)
	HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error)
}
