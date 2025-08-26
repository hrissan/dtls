package statemachine

// Motivation for event-based interface is we have a single datagram reading goroutine,
// and so for short requests we can call user handler on the same buffer we used for reading
// and decrypting, and user code often can parse the same bytes and make some state machine
// transition of its own, while everything resides in L1 cache.

// Also, event-based API is more basic than goroutine-based, you can easily make
// goroutine-based API over event-based one, but not vice versa.

// All OnXXX methods are called under connection lock.
// Statemachine of your protocol must work under the same lock
// If you need to change your statemachine from another goroutine,
// you must call Connection.Lock() / defer Connection.Unlock()
// See examples
type ConnectionHandler interface {
	OnConnectLocked()
	// application must remove connection from all data structures
	// connection will be reused and become invalid immediately after method returns
	OnDisconnectLocked(err error)

	// if connection was register for send with transport, this method will be called
	// in the near future. record is allocated and resized to maximum size application
	// is allowed to write.
	// Application sets send = true, if it filled record. recordSize is # of bytes filled
	// (recordSize can be 0 to send 0-size record, if recordSize > len(record), then panic)
	// Application sets moreData if it still has more data to send.
	// Application can set send = false, and moreData = true only in case it did not want
	// to send short record (application may prefer to send longer record on the next call).
	OnWriteRecordLocked(recordBody []byte) (recordSize int, send bool, signalWriteable bool, err error)

	// every record sent will be delivered as is. Sent empty records are delivered as empty records.
	// record points to buffer inside transport and must not be retained.
	// bytes are guaranteed to be valid only during the call.
	// if application returns error, connection close will be initiated, expect OnDisconnect in the near future.
	OnReadRecordLocked(recordBody []byte) error
}

type TransportHandler interface {
	OnNewConnection() (*Connection, ConnectionHandler)
}
