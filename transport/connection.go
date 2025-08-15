package transport

type Connection interface {
	// connection will be scheduled for shut down with
	// OnDisconnect called in the near future
	Shutdown()

	// Connectin has no Close() method, because when Close() is called,
	// there could already be started call of method in ConnectionHandler,
	// which we cannot cheaply sync with. So we cannot give guarantee that
	// after Close() finishes, there would be no calls to ConnectionHandler

	// connection will be scheduled for sending with
	// OnWriteApplicationRecord called in the near future
	SetWantWriteApplicationRecord()
}

type ConnectionHandler interface {
	// application must remove connection from all data structures
	// connection will be reused and become invalid immediately after method returns
	OnDisconnect(err error)

	// if connection was register for send with transport, this method will be called
	// in the near future. record is allocated and resized to maximum size application
	// is allowed to write.
	// There is 3 possible outcomes
	// 1. Application already has nothing to send,
	//    should return <anything>, false, false
	// 2. Application filled record, and now has nothing to send
	//    should return recordSize, true, false. recordSize can be 0, then empty record will be sent.
	// 3. Application filled record, but still has more data to send, which did not fit
	//    should return recordSize, true, true. recordSize can be 0, empty record will be sent
	// returning recordSize > len(record) || send = false, addToSendQueue = true is immediate panic (API violation)
	OnWriteApplicationRecord(record []byte) (recordSize int, send bool, addToSendQueue bool)

	// every record sent will be delivered as is. Sent empty records are delivered as empty records.
	// record points to buffer inside transport and must not be retained.
	// bytes are guaranteed to be valid only during the call.
	// if application returns error, connection close will be initiated, expect OnDisconnect in the near future.
	OnReadApplicationRecord(record []byte) error
}
