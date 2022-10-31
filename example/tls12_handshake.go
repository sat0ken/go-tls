package main

import (
	"crypto/tls"
	"fmt"
	"gotls"
)

// TLS1.2ハンドシェイク
func main() {

	conn := gotls.Conn("127.0.0.1", 10443)

	var tlsinfo gotls.TLSInfo
	var hello gotls.ClientHello
	var hellobyte []byte
	tlsinfo, hellobyte = hello.NewClientHello(gotls.TLS1_2, false, gotls.UintTo2byte(tls.TLS_RSA_WITH_AES_128_GCM_SHA256))

	fmt.Printf("client random : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)

	// handshakeメッセージはverify_data作成のために保存しておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, hellobyte[5:]...)

	var tlsproto []gotls.TLSProtocol
	var tlsbyte []byte

	tlsproto, tlsbyte = gotls.WriteTLS(conn, hellobyte)

	// parseしたServerHello, Certificates, ServerHelloDoneをappend
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, tlsbyte...)

	// ServerHello, ServerCertificate, ServerKeyEXchangeを処理する
	tlsinfo = gotls.HandleServerHandshake(tlsproto, tlsinfo)

	fmt.Printf("ClientRandom : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)
	fmt.Printf("ServerRandom : %x\n", tlsinfo.MasterSecretInfo.ServerRandom)

	// ClientKeyExchangeメッセージを作る
	// premaster secretをサーバの公開鍵で暗号化する
	// 暗号化したらTLSのMessage形式にしてClientKeyExchangeを作る
	var clientKeyExchange gotls.ClientKeyExchange
	var clientKeyExchangeBytes []byte
	// RSA鍵交換のとき
	clientKeyExchangeBytes, tlsinfo.MasterSecretInfo.PreMasterSecret = clientKeyExchange.NewClientKeyRSAExchange(tlsinfo.ServerPublicKey)
	// 生成した公開鍵をClientKeyExchangeにセットする
	//clientKeyExchangeBytes = clientKeyExchange.NewClientKeyECDHAExchange(tlsinfo.ECDHEKeys.PublicKey)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientKeyExchangeBytes[5:]...)

	// ChangeCipherSpecメッセージを作る
	changeCipher := gotls.NewChangeCipherSpec()

	// 鍵を作る
	tlsinfo.MasterSecretInfo.MasterSecret, tlsinfo.KeyBlock = gotls.CreateMasterandKeyblock(tlsinfo.MasterSecretInfo)

	var verifyData []byte
	verifyData = gotls.CreateVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, gotls.CLientFinishedLabel, tlsinfo.Handshakemessages)
	finMessage := []byte{gotls.HandshakeTypeFinished}
	finMessage = append(finMessage, gotls.UintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	// 送ったClient finishedを入れる、Serverからのfinishedと照合するため
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, finMessage...)

	rheader := gotls.NewTLSRecordHeader("Handshake", uint16(len(finMessage)))
	encryptFin := gotls.EncryptClientMessage(rheader, finMessage, tlsinfo)

	// ClientKeyexchange, ChangeCipehrspec, ClientFinsihedを全部まとめる
	var all []byte
	all = append(all, clientKeyExchangeBytes...)
	all = append(all, changeCipher...)
	all = append(all, encryptFin...)

	tlsproto, tlsbyte = gotls.WriteTLS(conn, all)

	//syscall.Write(sock, all)
	//for {
	//	recvBuf := make([]byte, 1500)
	//	_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
	//	if err != nil {
	//		log.Fatalf("read err : %v", err)
	//	}
	//	// 0byteがChangeCipherSpecであるか
	//	if bytes.HasPrefix(recvBuf, []byte{gotls.HandshakeTypeChangeCipherSpec}) {
	//		// 6byteからServerFinishedMessageになるのでそれをunpackする
	//		serverfin := gotls.DecryptServerMessage(recvBuf[6:51], tlsinfo, gotls.ContentTypeHandShake)
	//		verify := gotls.CreateVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, gotls.ServerFinishedLabel, tlsinfo.Handshakemessages)
	//
	//		if bytes.Equal(serverfin[4:], verify) {
	//			fmt.Printf("server fin : %x, client verify : %x, verify is ok !!\n", serverfin[4:], verify)
	//		}
	//	}
	//	break
	//}

	//送って受け取ったらシーケンスを増やす
	tlsinfo.ClientSequenceNum++

	//req := NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	//reqbyte := req.reqtoByteArr(req)
	//encAppdata := encryptClientMessage(NewTLSRecordHeader("AppDada", uint16(len(reqbyte))), reqbyte, tlsinfo)

	//fmt.Printf("appdata : %x\n", reqbyte)

	//appdata := []byte("hello\n")
	//encAppdata := gotls.EncryptClientMessage(gotls.NewTLSRecordHeader("AppDada", uint16(len(appdata))), appdata, tlsinfo)
	//syscall.Write(sock, encAppdata)
	//
	//time.Sleep(10 * time.Millisecond)
	//
	//for {
	//	recvBuf := make([]byte, 1500)
	//	_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
	//	if err != nil {
	//		log.Fatalf("read err : %v", err)
	//	}
	//	// 0byteがApplication Dataであるか
	//	if bytes.HasPrefix(recvBuf, []byte{gotls.ContentTypeApplicationData}) {
	//		// 6byteからServerFinishedMessageになるのでそれをunpackする
	//		length := binary.BigEndian.Uint16(recvBuf[3:5])
	//		serverappdata := gotls.DecryptServerMessage(recvBuf[0:length+5], tlsinfo, gotls.ContentTypeApplicationData)
	//		//fmt.Printf("app data from server : %x\n", appdata)
	//		fmt.Printf("app data from server : %s\n", string(serverappdata))
	//	}
	//	break
	//}
	//tlsinfo.ClientSequenceNum++
	//
	//encryptAlert := gotls.EncryptClientMessage(gotls.NewTLSRecordHeader("Alert", 2), []byte{0x01, 0x00}, tlsinfo)
	//syscall.Write(sock, encryptAlert)
	//time.Sleep(10 * time.Millisecond)
	//syscall.Close(sock)
}
