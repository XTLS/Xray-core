package connectiontracker

import (
	"context"

	"github.com/xtls/xray-core/common"
	xrayfeatures "github.com/xtls/xray-core/features"
)

// Feature exposes the shared connection tracker manager through Xray's
// feature-resolution system.
type Feature interface {
	xrayfeatures.Feature
	Manager() *Manager
}

func FeatureType() interface{} {
	return (*Feature)(nil)
}

// Config is the config placeholder for explicitly constructing the tracker
// feature.
type Config struct{}

// Service owns the singleton manager for one Xray instance.
type Service struct {
	manager *Manager
}

func NewService() *Service {
	return &Service{
		manager: NewManager(),
	}
}

func (*Service) Type() interface{} {
	return FeatureType()
}

func (s *Service) Start() error {
	return nil
}

func (s *Service) Close() error {
	return s.manager.Close()
}

func (s *Service) Manager() *Manager {
	return s.manager
}

var _ Feature = (*Service)(nil)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(context.Context, interface{}) (interface{}, error) {
		return NewService(), nil
	}))
}
