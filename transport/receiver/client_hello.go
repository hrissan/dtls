package receiver

import (
	"crypto/sha256"
	"errors"
	"hash"
	"log"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
	"golang.org/x/crypto/curve25519"
)

func (rc *Receiver) OnClientHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort) {
	if err := IsSupportedClientHello(&msg); err != nil {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, err)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.CookieSet {
		if handshakeHdr.MessageSeq != 0 {
			rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithoutCookieMsgSeqNum)
			// TODO - generate alert
			return
		}
		transcriptHasher := sha256.New()
		addMessageDataTranscript(transcriptHasher, messageData)
		var initialHelloTranscriptHash [cookie.MaxTranscriptHashLength]byte
		transcriptHasher.Sum(initialHelloTranscriptHash[:0])

		keyShareSet := !msg.Extensions.KeyShare.X25519PublicKeySet
		ck := rc.cookieState.CreateCookie(initialHelloTranscriptHash, keyShareSet, addr, time.Now())
		rc.opts.Stats.CookieCreated(addr)

		hrrDatagram, _ := rc.snd.PopHelloRetryDatagram()
		hrrDatagram = generateStatelessHRR(hrrDatagram, ck, keyShareSet)
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash: %x\n", hrrHash[:])
		rc.snd.SendHelloRetryDatagram(hrrDatagram, addr)
		return
	}
	if handshakeHdr.MessageSeq != 1 {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithCookieMsgSeqNum)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrSupportOnlyX25519)
		// TODO - generate alert
		return
	}
	valid, age, initialHelloTranscriptHash, keyShareSet := rc.cookieState.IsCookieValid(addr, msg.Extensions.Cookie, time.Now())
	if age > rc.opts.CookieValidDuration {
		valid = false
	}
	rc.opts.Stats.CookieChecked(valid, age, addr)
	if !valid {
		// generate alert
		return
	}
	hrrDatagram, _ := rc.snd.PopHelloRetryDatagram()
	hrrDatagram = generateStatelessHRR(hrrDatagram, msg.Extensions.Cookie, keyShareSet)
	hrrHash := sha256.Sum256(hrrDatagram)
	log.Printf("serverHRRHash: %x\n", hrrHash[:])

	log.Printf("start handshake keyShareSet=%v initial hello transcript hash(hex): %x", keyShareSet, initialHelloTranscriptHash)
	var kk keys.Keys
	//hctx, ok := rc.handshakes[addr]
	//if !ok {
	//	hctx = &HandshakeContext{
	//		LastActivity:          time.Now(),
	//		NextMessageSeqReceive: 2, // ClientHello, ClientHello
	//		NextMessageSeqSend:    2, // HRR, ServerHello
	//	}
	rc.opts.Rnd.Read(kk.ServerRandom[:])
	rc.opts.Rnd.Read(kk.X25519Secret[:])
	x25519Public, err := curve25519.X25519(kk.X25519Secret[:], curve25519.Basepoint)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	//rc.handshakes[addr] = hctx

	datagram, _ := rc.snd.PopHelloRetryDatagram()
	helloRetryRequest := format.ServerHello{
		Random:      kk.ServerRandom,
		CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
	helloRetryRequest.Extensions.KeyShareSet = true
	helloRetryRequest.Extensions.KeyShare.X25519PublicKeySet = true
	copy(helloRetryRequest.Extensions.KeyShare.X25519PublicKey[:], x25519Public)
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		Epoch:          0,
		SequenceNumber: 1,
	}
	msgHeader := format.MessageHandshakeHeader{
		HandshakeType:  format.HandshakeTypeServerHello,
		Length:         0,
		MessageSeq:     1,
		FragmentOffset: 0,
		FragmentLength: 0,
	}
	// first reserve space for headers by writing with not all variables set
	datagram = recordHdr.Write(datagram, 0) // reserve space
	recordHeaderSize := len(datagram)
	datagram = msgHeader.Write(datagram) // reserve space
	msgHeaderSize := len(datagram) - recordHeaderSize
	datagram = helloRetryRequest.Write(datagram)
	msgBodySize := len(datagram) - recordHeaderSize - msgHeaderSize
	msgHeader.Length = uint32(msgBodySize)
	msgHeader.FragmentLength = msgHeader.Length
	// now overwrite reserved space
	_ = recordHdr.Write(datagram[:0], msgHeaderSize+msgBodySize)
	_ = msgHeader.Write(datagram[recordHeaderSize:recordHeaderSize])
	rc.snd.SendHelloRetryDatagram(datagram, addr)

	transcriptHasher := sha256.New()
	syntheticHashData := []byte{format.HandshakeTypeMessageHash, 0, 0, sha256.Size}
	_, _ = transcriptHasher.Write(syntheticHashData)
	_, _ = transcriptHasher.Write(initialHelloTranscriptHash[:sha256.Size])
	addMessageDataTranscript(transcriptHasher, hrrDatagram[13:]) // skip record header
	addMessageDataTranscript(transcriptHasher, messageData)
	addMessageDataTranscript(transcriptHasher, datagram[13:]) // skip record header

	var handshakeTranscriptHash [cookie.MaxTranscriptHashLength]byte
	transcriptHasher.Sum(handshakeTranscriptHash[:0])

	sharedSecret, err := curve25519.X25519(kk.X25519Secret[:], msg.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	kk.ComputeHandshakeKeys(sharedSecret, handshakeTranscriptHash[:sha256.Size])
	//	return
	//}
	// TODO - start Handshake
}

var ErrSupportOnlyDTLS13 = errors.New("we support only DTLS 1.3")
var ErrSupportOnlyTLS_AES_128_GCM_SHA256 = errors.New("we support only TLS_AES_128_GCM_SHA256 ciphersuite for now")
var ErrSupportOnlyX25519 = errors.New("we support only X25519 key share for now")
var ErrClientHelloWithoutCookieMsgSeqNum = errors.New("client hello without cookie must have msg_seq_num 0")
var ErrClientHelloWithCookieMsgSeqNum = errors.New("client hello with cookie must have msg_seq_num 1")

func IsSupportedClientHello(msg *format.ClientHello) error {
	if !msg.Extensions.SupportedVersions.DTLS_13 {
		return ErrSupportOnlyDTLS13
	}
	if !msg.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 {
		return ErrSupportOnlyTLS_AES_128_GCM_SHA256
	}
	if !msg.Extensions.SupportedGroups.X25519 {
		return ErrSupportOnlyX25519
	}
	return nil
}

func generateStatelessHRR(datagram []byte, ck cookie.Cookie, keyShareSet bool) []byte {
	helloRetryRequest := format.ServerHello{
		CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	helloRetryRequest.SetHelloRetryRequest()
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
	if keyShareSet {
		helloRetryRequest.Extensions.KeyShareSet = true
		helloRetryRequest.Extensions.KeyShare.KeyShareHRRSelectedGroup = format.SupportedGroup_X25519
	}
	helloRetryRequest.Extensions.CookieSet = true
	helloRetryRequest.Extensions.Cookie = ck
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		Epoch:          0,
		SequenceNumber: 0,
	}
	msgHeader := format.MessageHandshakeHeader{
		HandshakeType:  format.HandshakeTypeServerHello,
		Length:         0,
		MessageSeq:     0,
		FragmentOffset: 0,
		FragmentLength: 0,
	}
	// first reserve space for headers by writing with not all variables set
	datagram = recordHdr.Write(datagram, 0) // reserve space
	recordHeaderSize := len(datagram)
	datagram = msgHeader.Write(datagram) // reserve space
	msgHeaderSize := len(datagram) - recordHeaderSize
	datagram = helloRetryRequest.Write(datagram)
	msgBodySize := len(datagram) - recordHeaderSize - msgHeaderSize
	msgHeader.Length = uint32(msgBodySize)
	msgHeader.FragmentLength = msgHeader.Length
	// now overwrite reserved space
	_ = recordHdr.Write(datagram[:0], msgHeaderSize+msgBodySize)
	_ = msgHeader.Write(datagram[recordHeaderSize:recordHeaderSize])
	return datagram
}

func addMessageDataTranscript(transcriptHasher hash.Hash, messageData []byte) {
	_, _ = transcriptHasher.Write(messageData[:4])
	_, _ = transcriptHasher.Write(messageData[12:])
}
