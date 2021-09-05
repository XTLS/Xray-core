package observatory

func (o *Observer) UpdateStatus(result *OutboundStatus) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()

	if location := o.findStatusLocationLockHolderOnly(result.OutboundTag); location != -1 {
		o.status[location] = result
	} else {
		o.status = append(o.status, result)
	}
}
