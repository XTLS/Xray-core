package xray_vless_callbacks

import (
	"github.com/4nd3r5on/Xray-core/common/idsyncmap"
	"github.com/4nd3r5on/Xray-core/proxy/vless"
)

type (
	CallbackOnData struct {
		Exec func() error
	}
	CallbackOnProcess struct {
		Exec func(account *vless.MemoryAccount) error
	}
)

type CallbackManager struct {
	CbsOnData    idsyncmap.IDSyncMap[CallbackOnData]
	CbsOnProcess idsyncmap.IDSyncMap[CallbackOnProcess]
}

func (cm *CallbackManager) ExecOnData() (id int32, err error) {
	for id, callback := range cm.CbsOnData.Get() {
		err = callback.Exec()
		if err != nil {
			return id, err
		}
	}
	return id, nil
}

func (cm *CallbackManager) ExecOnProcess(account *vless.MemoryAccount) (id int32, err error) {
	for id, callback := range cm.CbsOnProcess.Get() {
		err = callback.Exec(account)
		if err != nil {
			return id, err
		}
	}
	return id, nil
}

func NewCallbackManager() *CallbackManager {
	return &CallbackManager{
		CbsOnData:    idsyncmap.NewIDSyncMap[CallbackOnData](),
		CbsOnProcess: idsyncmap.NewIDSyncMap[CallbackOnProcess](),
	}
}
