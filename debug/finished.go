package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	_ "crypto/tls"
	"encoding/hex"

	"crypto/x509"
	"fmt"
	"log"
)

func strtoByte(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

var finishedbytes = []byte{
	0x16, 0x03, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x46, 0x6d,
	0xdf, 0x32, 0xc2, 0x2c, 0x96, 0xf0, 0xf0, 0x52,
	0x6e, 0x26, 0xc7, 0xce, 0xe5, 0x9b, 0x62, 0x96,
	0xcf, 0xc5, 0xc7, 0x8c, 0x2b, 0xb3, 0x3f, 0x53,
	0xbb, 0x13, 0x7e, 0x36, 0xcd,
}

var clienthello = "1603010200010001fc0303fb75e76a09747787d75e5dd494a3ccfbf4756f4c681f27851fbb79941e4faab8209c686a0a2244e5e71aac8c7450aaac7179c9bce437fa03fe1db7efef62e957cd000a130213031301009c00ff010001a90000000e000c0000096c6f63616c686f7374000b000403000102000a00160014001d0017001e0019001801000101010201030104337400000010000b000908687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d002023f24738be38d344f0705c6c85a50b073f48ed850b65b3537f3f54bb5429f94f001500eb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

var serverHello = "1603030046020000420303000000000000000000000000000000000000000000000000000000000000000000009c00001aff010001000010000b000908687474702f312e31000b00020100"

var serverCertificate = "16030304250b00042100041e00041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee"

var serverhellodone = "16030300040e000000"

var clientkeyexchange = "16030301061000010201002bda999e3011b313abf4c66ced52196125354ba4959748b2ee385dce9d7e1b6d9438392843948a0d201aef19619d43e18cd83052d9fcc514376bdfbbac128cb074ebc8e82ff7530ddd4b62f3f3cc560f24285675f080da904407da0d71231b6a6792661f88d8bfbfead26b9eba6c7083200d4339173e263cdccd8cd6477e8307844531e65a4df0b8077d7746915905de70b002ba366e0bb68b584e07aeec0bf6dad2112b97e431200e2d517b4dcd7e9f325a88718d2c7019dc65624343e8ab3b0b811ed75349646d631f4a854201b4897753c81c53b2358f236d7b1593f93c7e8c21cb59c2c384941657dc991217e0b47bd108cf617d22cbf19347ab8182ba72"

// 固定のラベル
var MasterSecretLable = []byte(`master secret`)
var FinishedLabel = []byte(`client finished`)
var KeyLabel = []byte(`key expansion`)

func phash(secret, seed []byte, prfLength int) []byte {
	result := make([]byte, prfLength)
	mac := hmac.New(sha256.New, secret)
	mac.Write(seed)

	// A(1)
	a := mac.Sum(nil)
	length := 0

	// 48byteになるまで計算する
	for length < len(result) {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)
		copy(result[length:], b)
		length += len(b)

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return result
}

// https://www.ipa.go.jp/security/rfc/RFC5246-08JA.html#081
// ClientKeyExchangeのときに生成したpremaster secretと
// ClientHelloで送ったrandom, ServerHelloで受信したrandomをもとに48byteのmaster secretを生成する
func prf(secret, label, clientServerRandom []byte, prfLength int) []byte {
	var seed []byte
	seed = append(seed, label...)
	seed = append(seed, clientServerRandom...)
	return phash(secret, seed, prfLength)
}

func norandam(length int) []byte {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = 0x00
	}
	return b
}

func mastersecret() {

	//premaster := []byte{0x03, 0x03}
	//premaster = append(premaster, norandam(46)...)
	premaster := strtoByte("0303a7ac1e57c403c1fca6fb9d07ce47553cd8ae3ad0b2d7a5f731d80a48890e70a4a6fdb04b5a5490023698a4a9e302")

	clientRandom := norandam(32)
	serverRandom := norandam(32)

	var clientServerRandomByte []byte
	clientServerRandomByte = append(clientServerRandomByte, clientRandom...)
	clientServerRandomByte = append(clientServerRandomByte, serverRandom...)

	ms := prf(premaster, MasterSecretLable, clientServerRandomByte, 48)

	var serverclientrandomByte []byte
	serverclientrandomByte = append(serverclientrandomByte, serverRandom...)
	serverclientrandomByte = append(serverclientrandomByte, clientRandom...)

	keyblock := prf(ms, KeyLabel, serverclientrandomByte, 40)

	fmt.Printf("client_write_key is %x\n", keyblock[0:16])
	fmt.Printf("server_write_key is %x\n", keyblock[16:32])
	fmt.Printf("client_write_IV  is %x\n", keyblock[32:36])
	fmt.Printf("server_write_IV  is %x\n", keyblock[36:40])

	var hs_messages []byte
	hs_messages = append(hs_messages, strtoByte(clienthello)...)
	hs_messages = append(hs_messages, strtoByte(serverHello)...)
	hs_messages = append(hs_messages, strtoByte(serverCertificate)...)
	hs_messages = append(hs_messages, strtoByte(serverhellodone)...)
	hs_messages = append(hs_messages, strtoByte(clientkeyexchange)...)

	hasher := sha256.New()
	hasher.Write(hs_messages)

	verify_data := prf(ms, FinishedLabel, hasher.Sum(nil), 12)
	fmt.Printf("verify_data is %x\n", verify_data)

	encrpytdata := encrpyt(keyblock[0:16], verify_data, keyblock[32:36])
	fmt.Printf("encrpytdata is %x\n", encrpytdata)

}

func encrpyt(key, plaintext, prefixnonce []byte) []byte {
	add := norandam(8)
	add = append(add, []byte{0x14, 0x00, 0x00, 0x0c}...)

	block, _ := aes.NewCipher(key)
	nonce := append(prefixnonce, norandam(8)...)
	aesgcm, _ := cipher.NewGCM(block)

	return aesgcm.Seal(nil, nonce, plaintext, add)
}

func decrypt() {
	key, _ := hex.DecodeString("475f58d5ca2aa6b36add62077ea4a340")
	ciphertext := []byte{0x51, 0x46, 0x6d, 0xdf, 0x0b, 0x80, 0xa1, 0xb9, 0xd7, 0xf3, 0x2f, 0xa8, 0x0d, 0x56, 0x24, 0x43}
	//nonce, _ := hex.DecodeString("0bcd1746")
	nonce := []byte{0x0b, 0xcd, 0x17, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	aad := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x28}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("NewCipher err : %s\n", err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("NewGCM err : %s\n", err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		log.Fatalf("aesgcm Open err : %s\n", err.Error())
	}

	fmt.Printf("%x\n", plaintext)
}

func main() {
	mastersecret()
	//fmt.Printf("master secret is %x\n", ms)
}

func __main() {
	certfile, err := tls.LoadX509KeyPair("./pems/my-tls.com+2.pem", "./pems/my-tls.com+2-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certfile.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	_ = cert
	//fmt.Println(cert.Issuer)
	//mastersecret()
	//secret, err := rsa.DecryptPKCS1v15(rand.Reader, certfile.PrivateKey.(*rsa.PrivateKey), finishedbytes)
	//if err != nil {
	//	log.Fatalf("create premaster secret err : %v\n", err)
	//}
	//fmt.Printf("%x\n", secret)

	var protocols []byte
	protocols = append(protocols, clienthello...)
	protocols = append(protocols, serverHello...)
	protocols = append(protocols, serverCertificate...)
	protocols = append(protocols, serverhellodone...)

	hasher := sha256.New()
	hasher.Write(protocols)
	messsage := hasher.Sum(nil)
	_ = messsage

	//ms := mastersecret()
	//fmt.Printf("master_secret : %x\n", ms)
	//
	//result := prf(ms, FinishedLabel, messsage)
	////
	//fmt.Printf("verify_data : %x\n", result)

}
