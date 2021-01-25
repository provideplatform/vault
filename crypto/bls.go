package crypto

// BLS is the internal struct for a BLS keypair
type BLS struct {
	PrivateKey *[]byte
	PublicKey  *[]byte
}
