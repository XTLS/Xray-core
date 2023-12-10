package xray_vless_callback

type (
	CallbackOnConnect struct {
		Exec func() error
	}
	CallbackOnDisconnect struct {
		Exec func() error
	}
	CallbackOnData struct {
		Exec func() error
	}
)

type CallbackManagerConfig struct {
	OnConnect    []CallbackOnConnect
	OnDisconnect []CallbackOnDisconnect
	OnData       []CallbackOnData
}

type Callbacks interface {
	ExecOnConnect() error
	ExecOnDisconnect() error
	ExecOnData() error
}

type CallbackManager interface {
	Callbacks
}

type callbackManager struct {
	OnConnect    []CallbackOnConnect
	OnDisconnect []CallbackOnDisconnect
	OnData       []CallbackOnData
}

func (cm *callbackManager) ExecOnConnect() error {
	var err error
	for _, callback := range cm.OnConnect {
		if err = callback.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (cm *callbackManager) ExecOnDisconnect() error {
	var err error
	for _, callback := range cm.OnDisconnect {
		if err = callback.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (cm *callbackManager) ExecOnData() error {
	var err error
	for _, callback := range cm.OnData {
		if err = callback.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func NewCallbackManager(cfg CallbackManagerConfig) CallbackManager {
	return &callbackManager{
		OnConnect:    cfg.OnConnect,
		OnDisconnect: cfg.OnDisconnect,
		OnData:       cfg.OnData,
	}
}
