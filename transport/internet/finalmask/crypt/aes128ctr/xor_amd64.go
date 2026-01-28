package aes128ctr

//go:noescape
func xorfwd(x []byte)

//go:noescape
func xorbkd(x []byte)
