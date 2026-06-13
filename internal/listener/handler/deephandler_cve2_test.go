package handler

import (
	"encoding/binary"
	"testing"
)

// --- AMQP default-credential capture (RabbitMQ guest/guest) ---

// amqpStartOk builds a Connection.StartOk method frame carrying SASL PLAIN
// credentials (the \0user\0pass blob), which is what the handler parses.
func amqpStartOk(user, pass string) []byte {
	plain := append([]byte{0}, user...)
	plain = append(plain, 0)
	plain = append(plain, pass...)

	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, 10) // class Connection
	payload = binary.BigEndian.AppendUint16(payload, 11) // method StartOk
	payload = binary.BigEndian.AppendUint32(payload, 0)  // client-properties: empty table
	payload = append(payload, byte(len("PLAIN")))        // mechanism: short string
	payload = append(payload, "PLAIN"...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(plain))) // response: long string
	payload = append(payload, plain...)
	payload = append(payload, byte(len("en_US"))) // locale: short string
	payload = append(payload, "en_US"...)

	frame := []byte{1, 0, 0} // type=method, channel 0
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	frame = append(frame, 0xCE) // frame-end
	return frame
}

func amqpClientStream(user, pass string) string {
	hdr := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}
	return string(hdr) + string(amqpStartOk(user, pass))
}

func TestAMQPDefaultGuestLogin(t *testing.T) {
	res, _ := roundtrip(t, &amqp{}, amqpClientStream("guest", "guest"))
	if res.Meta["auth_user"] != "guest" || res.Meta["auth_pass"] != "guest" {
		t.Fatalf("creds not parsed: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
	for _, want := range []string{"amqp-credential-attempt", "amqp-default-guest-login", "default-credential-attempt"} {
		if !hasAnom(res, want) {
			t.Errorf("missing anomaly %q: %v", want, res.Meta["anomalies"])
		}
	}
}

func TestAMQPNonDefaultCredNotGuest(t *testing.T) {
	res, _ := roundtrip(t, &amqp{}, amqpClientStream("svc-app", "s3cr3t-token"))
	if !hasAnom(res, "amqp-credential-attempt") {
		t.Errorf("credential attempt not flagged: %v", res.Meta["anomalies"])
	}
	if hasAnom(res, "amqp-default-guest-login") {
		t.Errorf("non-default cred wrongly flagged as default guest login")
	}
}

// --- NFS MOUNT protocol (showmount) recognition ---

// rpcMountCall builds a record-marked SunRPC CALL to mountd (program 100005)
// with AUTH_NULL cred/verf and no procedure arguments.
func rpcMountCall(proc uint32) string {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 0)      // xid
	b = binary.BigEndian.AppendUint32(b, 0)      // msg_type CALL
	b = binary.BigEndian.AppendUint32(b, 2)      // RPC version 2
	b = binary.BigEndian.AppendUint32(b, 100005) // program mountd
	b = binary.BigEndian.AppendUint32(b, 3)      // version 3
	b = binary.BigEndian.AppendUint32(b, proc)   // procedure
	b = binary.BigEndian.AppendUint32(b, 0)      // cred flavor AUTH_NULL
	b = binary.BigEndian.AppendUint32(b, 0)      // cred length
	b = binary.BigEndian.AppendUint32(b, 0)      // verf flavor AUTH_NULL
	b = binary.BigEndian.AppendUint32(b, 0)      // verf length
	rec := binary.BigEndian.AppendUint32(nil, uint32(len(b))|0x80000000)
	return string(rec) + string(b)
}

func TestNFSShowmountEnum(t *testing.T) {
	res, _ := roundtrip(t, &nfs{}, rpcMountCall(5)) // EXPORT
	if res.Meta["rpc_program_name"] != "mountd" {
		t.Fatalf("program not recognized as mountd: %v", res.Meta["rpc_program_name"])
	}
	if !hasAnom(res, "nfs-showmount-enum") {
		t.Errorf("showmount EXPORT not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["nfs_proc"] != "MOUNT/EXPORT" {
		t.Errorf("proc mislabeled: %v", res.Meta["nfs_proc"])
	}
}

func TestNFSMountAttempt(t *testing.T) {
	res, _ := roundtrip(t, &nfs{}, rpcMountCall(1)) // MNT
	if !hasAnom(res, "nfs-mount-attempt") {
		t.Errorf("MNT not flagged: %v", res.Meta["anomalies"])
	}
}
