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
