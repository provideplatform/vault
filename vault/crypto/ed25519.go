package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/ed25519"
)

const (
	// PrefixByteSeed is the version byte used for encoded seeds
	PrefixByteSeed PrefixByte = 18 << 3 // Base32-encodes to 'S...'

	// PrefixBytePrivate is the version byte used for encoded private keys
	PrefixBytePrivate PrefixByte = 15 << 3 // Base32-encodes to 'P...'

	// PrefixByteUnknown is for unknown prefixes.
	PrefixByteUnknown PrefixByte = 23 << 3 // Base32-encodes to 'X...'
)

// Errors
var (
	ErrInvalidPrefixByte = errors.New("invalid prefix byte")
	ErrInvalidKey        = errors.New("invalid key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidSeedLen    = errors.New("invalid seed length")
	ErrInvalidSeed       = errors.New("invalid seed")
	ErrInvalidEncoding   = errors.New("invalid encoded key")
	ErrInvalidSignature  = errors.New("signature verification failed")
	ErrCannotSign        = errors.New("can not sign, no private key available")
	ErrPublicKeyOnly     = errors.New("no seed or private key available")
	ErrIncompatibleKey   = errors.New("incompatible key")

	ErrInvalidChecksum = errors.New("nkeys: invalid checksum")

	// Set our encoding to not include padding '=='
	b32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

	crc16tab = [256]uint16{
		0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
		0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
		0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
		0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
		0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
		0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
		0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
		0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
		0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
		0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
		0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
		0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
		0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
		0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
		0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
		0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
		0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
		0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
		0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
		0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
		0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
		0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
		0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
		0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
		0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
		0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
		0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
		0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
		0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
		0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
		0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
		0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
	}
)

// keypair is the internal struct for a keypair using seed.
type keypair struct {
	seed []byte
}

// A KeyPair from a public key capable of verifying only.
type pubkey struct {
	pre PrefixByte
	pub ed25519.PublicKey
}

// PrefixByte is a lead byte representing the type.
type PrefixByte byte

// KeyPair provides the central interface to nkeys.
type KeyPair interface {
	Seed() ([]byte, error)
	PublicKey() (string, error)
	PrivateKey() ([]byte, error)
	Sign(input []byte) ([]byte, error)
	Verify(input []byte, sig []byte) error
	Wipe()
}

// CreatePair will create a KeyPair based on the rand entropy and a type/prefix byte. rand can be nil.
func CreatePair(prefix PrefixByte) (KeyPair, error) {
	var rawSeed [32]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	seed, err := EncodeSeed(prefix, rawSeed[:])
	if err != nil {
		return nil, err
	}
	return &keypair{seed}, nil
}

// FromPublicKey will create a KeyPair capable of verifying signatures.
func FromPublicKey(public string) (KeyPair, error) {
	raw, err := decode([]byte(public))
	if err != nil {
		return nil, err
	}
	pre := PrefixByte(raw[0])
	if err := checkValidPublicPrefixByte(pre); err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &pubkey{pre, raw[1:]}, nil
}

// FromSeed will create a KeyPair capable of signing and verifying signatures.
func FromSeed(seed []byte) (KeyPair, error) {
	_, _, err := DecodeSeed(seed)
	if err != nil {
		return nil, err
	}
	copy := append([]byte{}, seed...)
	return &keypair{copy}, nil
}

// FromRawSeed will create a KeyPair from the raw 32 byte seed for a given type.
func FromRawSeed(prefix PrefixByte, rawSeed []byte) (KeyPair, error) {
	seed, err := EncodeSeed(prefix, rawSeed)
	if err != nil {
		return nil, err
	}
	return &keypair{seed}, nil
}

// rawSeed will return the raw, decoded 64 byte seed.
func (pair *keypair) rawSeed() ([]byte, error) {
	_, raw, err := DecodeSeed(pair.seed)
	return raw, err
}

// keys will return a 32 byte public key and a 64 byte private key utilizing the seed.
func (pair *keypair) keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := pair.rawSeed()
	if err != nil {
		return nil, nil, err
	}
	return ed25519.GenerateKey(bytes.NewReader(raw))
}

// Wipe will randomize the contents of the seed key
func (pair *keypair) Wipe() {
	io.ReadFull(rand.Reader, pair.seed)
	pair.seed = nil
}

// Seed will return the encoded seed.
func (pair *keypair) Seed() ([]byte, error) {
	return pair.seed, nil
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (pair *keypair) PublicKey() (string, error) {
	public, raw, err := DecodeSeed(pair.seed)
	if err != nil {
		return "", err
	}
	pub, _, err := ed25519.GenerateKey(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	pk, err := Encode(public, pub)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// PrivateKey will return the encoded private key for KeyPair.
func (pair *keypair) PrivateKey() ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return Encode(PrefixBytePrivate, priv)
}

// Sign will sign the input with KeyPair's private key.
func (pair *keypair) Sign(input []byte) ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, input), nil
}

// Verify will verify the input against a signature utilizing the public key.
func (pair *keypair) Verify(input []byte, sig []byte) error {
	pub, _, err := pair.keys()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// Encode will encode a raw key or seed with the prefix and crc16 and then base32 encoded.
func Encode(prefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(prefix); err != nil {
		return nil, err
	}

	var raw bytes.Buffer

	// write prefix byte
	if err := raw.WriteByte(byte(prefix)); err != nil {
		return nil, err
	}

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, b32Enc.EncodedLen(len(data)))
	b32Enc.Encode(buf, data)
	return buf[:], nil
}

// EncodeSeed will encode a raw key with the prefix and then seed prefix and crc16 and then base32 encoded.
func EncodeSeed(public PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPublicPrefixByte(public); err != nil {
		return nil, err
	}

	if len(src) != ed25519.SeedSize {
		return nil, ErrInvalidSeedLen
	}

	// In order to make this human printable for both bytes, we need to do a little
	// bit manipulation to setup for base32 encoding which takes 5 bits at a time.
	b1 := byte(PrefixByteSeed) | (byte(public) >> 5)
	b2 := (byte(public) & 31) << 3 // 31 = 00011111

	var raw bytes.Buffer

	raw.WriteByte(b1)
	raw.WriteByte(b2)

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, b32Enc.EncodedLen(len(data)))
	b32Enc.Encode(buf, data)
	return buf, nil
}

// IsValidEncoding will tell you if the encoding is a valid key.
func IsValidEncoding(src []byte) bool {
	_, err := decode(src)
	return err == nil
}

// decode will decode the base32 and check crc16 and the prefix for validity.
func decode(src []byte) ([]byte, error) {
	raw := make([]byte, b32Enc.DecodedLen(len(src)))
	n, err := b32Enc.Decode(raw, src)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]

	if len(raw) < 4 {
		return nil, ErrInvalidEncoding
	}

	var crc uint16
	checksum := bytes.NewReader(raw[len(raw)-2:])
	if err := binary.Read(checksum, binary.LittleEndian, &crc); err != nil {
		return nil, err
	}

	// ensure checksum is valid
	if err := validate(raw[0:len(raw)-2], crc); err != nil {
		return nil, err
	}

	return raw[:len(raw)-2], nil
}

// Decode will decode the base32 string and check crc16 and enforce the prefix is what is expected.
func Decode(expectedPrefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(expectedPrefix); err != nil {
		return nil, err
	}
	raw, err := decode(src)
	if err != nil {
		return nil, err
	}
	if prefix := PrefixByte(raw[0]); prefix != expectedPrefix {
		return nil, ErrInvalidPrefixByte
	}
	return raw[1:], nil
}

// DecodeSeed will decode the base32 string and check crc16 and enforce the prefix is a seed
// and the subsequent type is a valid type.
func DecodeSeed(src []byte) (PrefixByte, []byte, error) {
	raw, err := decode(src)
	if err != nil {
		return PrefixByteSeed, nil, err
	}
	// Need to do the reverse here to get back to internal representation.
	b1 := raw[0] & 248                          // 248 = 11111000
	b2 := (raw[0]&7)<<5 | ((raw[1] & 248) >> 3) // 7 = 00000111

	if PrefixByte(b1) != PrefixByteSeed {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	if checkValidPublicPrefixByte(PrefixByte(b2)) != nil {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	return PrefixByte(b2), raw[2:], nil
}

// Prefix returns PrefixBytes of its input
func Prefix(src string) PrefixByte {
	b, err := decode([]byte(src))
	if err != nil {
		return PrefixByteUnknown
	}
	prefix := PrefixByte(b[0])
	err = checkValidPrefixByte(prefix)
	if err == nil {
		return prefix
	}
	// Might be a seed.
	b1 := b[0] & 248
	if PrefixByte(b1) == PrefixByteSeed {
		return PrefixByteSeed
	}
	return PrefixByteUnknown
}

// IsValidPublicKey will decode and verify that the string is a valid encoded public key.
func IsValidPublicKey(src string) bool {
	b, err := decode([]byte(src))
	if err != nil {
		return false
	}
	if prefix := PrefixByte(b[0]); checkValidPublicPrefixByte(prefix) != nil {
		return false
	}
	return true
}

// checkValidPrefixByte returns an error if the provided value
// is not one of the defined valid prefix byte constants.
func checkValidPrefixByte(prefix PrefixByte) error {
	// switch prefix {
	// case PrefixByteOperator, PrefixByteServer, PrefixByteCluster,
	// 	PrefixByteAccount, PrefixByteUser, PrefixByteSeed, PrefixBytePrivate:
	// 	return nil
	// }
	// return ErrInvalidPrefixByte
	return nil
}

// checkValidPublicPrefixByte returns an error if the provided value
// is not one of the public defined valid prefix byte constants.
func checkValidPublicPrefixByte(prefix PrefixByte) error {
	// switch prefix {
	// case PrefixByteServer, PrefixByteCluster, PrefixByteOperator, PrefixByteAccount, PrefixByteUser:
	// 	return nil
	// }
	// return ErrInvalidPrefixByte
	return nil
}

func (p PrefixByte) String() string {
	return "unknown"
}

// CompatibleKeyPair returns an error if the KeyPair doesn't match expected PrefixByte(s)
func CompatibleKeyPair(kp KeyPair, expected ...PrefixByte) error {
	pk, err := kp.PublicKey()
	if err != nil {
		return err
	}
	pkType := Prefix(pk)
	for _, k := range expected {
		if pkType == k {
			return nil
		}
	}

	return ErrIncompatibleKey
}

// crc16 returns the 2-byte crc for the data provided.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc = ((crc << 8) & 0xffff) ^ crc16tab[((crc>>8)^uint16(b))&0x00FF]
	}
	return crc
}

// validate will check the calculated crc16 checksum for data against the expected.
func validate(data []byte, expected uint16) error {
	if crc16(data) != expected {
		return ErrInvalidChecksum
	}
	return nil
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (p *pubkey) PublicKey() (string, error) {
	pk, err := Encode(p.pre, p.pub)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// Seed will return an error since this is not available for public key only KeyPairs.
func (p *pubkey) Seed() ([]byte, error) {
	return nil, ErrPublicKeyOnly
}

// PrivateKey will return an error since this is not available for public key only KeyPairs.
func (p *pubkey) PrivateKey() ([]byte, error) {
	return nil, ErrPublicKeyOnly
}

// Sign will return an error since this is not available for public key only KeyPairs.
func (p *pubkey) Sign(input []byte) ([]byte, error) {
	return nil, ErrCannotSign
}

// Verify will verify the input against a signature utilizing the public key.
func (p *pubkey) Verify(input []byte, sig []byte) error {
	if !ed25519.Verify(p.pub, input, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// Wipe will randomize the public key and erase the pre byte.
func (p *pubkey) Wipe() {
	p.pre = '0'
	io.ReadFull(rand.Reader, p.pub)
}
