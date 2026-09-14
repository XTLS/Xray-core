package outbound

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

// Manager is to manage all outbound handlers.
type Manager struct {
	defaultHandler   atomic.Pointer[outbound.Handler]
	taggedHandler    *utils.TypedSyncMap[string, outbound.Handler]
	untaggedHandlers atomic.Pointer[[]outbound.Handler]
	running          atomic.Bool
	tagsCache        *utils.TypedSyncMap[string, []string]
	balancerPicker   routing.BalancerPicker
}

// New creates a new Manager.
func New(ctx context.Context, config *proxyman.OutboundConfig) (*Manager, error) {
	m := &Manager{
		taggedHandler: utils.NewTypedSyncMap[string, outbound.Handler](),
	}
	m.tagsCache = utils.NewTypedSyncMap[string, []string]()
	empty := make([]outbound.Handler, 0)
	m.untaggedHandlers.Store(&empty)
	_ = core.OptionalFeatures(ctx, func(router routing.Router) {
		if picker, ok := router.(routing.BalancerPicker); ok {
			m.balancerPicker = picker
		}
	})
	return m, nil
}

// Type implements common.HasType.
func (m *Manager) Type() interface{} {
	return outbound.ManagerType()
}

// Start implements core.Feature
func (m *Manager) Start() error {
	m.running.Store(true)

	var startErr error
	m.taggedHandler.Range(func(_ string, h outbound.Handler) bool {
		if err := h.Start(); err != nil {
			startErr = err
			return false
		}
		return true
	})
	if startErr != nil {
		return startErr
	}

	if untagged := m.untaggedHandlers.Load(); untagged != nil {
		for _, h := range *untagged {
			if err := h.Start(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Close implements core.Feature
func (m *Manager) Close() error {
	m.running.Store(false)

	var errs []error
	m.taggedHandler.Range(func(_ string, h outbound.Handler) bool {
		errs = append(errs, h.Close())
		return true
	})

	if untagged := m.untaggedHandlers.Load(); untagged != nil {
		for _, h := range *untagged {
			errs = append(errs, h.Close())
		}
	}

	return errors.Combine(errs...)
}

// GetDefaultHandler implements outbound.Manager.
func (m *Manager) GetDefaultHandler() outbound.Handler {
	if h := m.defaultHandler.Load(); h != nil {
		return *h
	}
	return nil
}

// GetHandler implements outbound.Manager.
func (m *Manager) GetHandler(tag string) outbound.Handler {
	if handler, found := m.taggedHandler.Load(tag); found {
		return handler
	}
	if strings.HasPrefix(tag, "balancer:") && m.balancerPicker != nil {
		targetTag := m.tryGetOutboundTagWithBalancer(tag, nil)
		if targetTag == "" {
			return nil
		}
		if handler, found := m.taggedHandler.Load(targetTag); found {
			return handler
		}
	}
	return nil
}

func (m *Manager) tryGetOutboundTagWithBalancer(tag string, parents []string) string {
	balancerTag := tag[len("balancer:"):]
	targetTag, err := m.balancerPicker.GetBalancerOutboundTag(balancerTag)
	if err != nil {
		errors.LogWarning(context.Background(), "failed to pick outbound from balancer [", balancerTag, "]: ", err)
		return ""
	}
	if strings.HasPrefix(targetTag, "balancer:") {
		if slices.Contains(parents, balancerTag) {
			errors.LogWarning(context.Background(), "detected balancer loop for [", balancerTag, "]")
			return ""
		}
		return m.tryGetOutboundTagWithBalancer(targetTag, append(parents, balancerTag))
	}
	return targetTag
}

// AddHandler implements outbound.Manager.
func (m *Manager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	m.tagsCache.Clear()

	m.defaultHandler.CompareAndSwap(nil, &handler)

	tag := handler.Tag()
	if len(tag) > 0 {
		if _, found := m.taggedHandler.LoadOrStore(tag, handler); found {
			return errors.New("existing tag found: " + tag)
		}
	} else {
		for {
			oldUntagged := m.untaggedHandlers.Load()
			newUntagged := make([]outbound.Handler, 0, len(*oldUntagged)+1)
			newUntagged = append(newUntagged, *oldUntagged...)
			newUntagged = append(newUntagged, handler)
			if m.untaggedHandlers.CompareAndSwap(oldUntagged, &newUntagged) {
				break
			}
		}
	}

	if m.running.Load() {
		return handler.Start()
	}

	return nil
}

// RemoveHandler implements outbound.Manager.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}

	m.tagsCache.Clear()

	m.taggedHandler.Delete(tag)
	if cur := m.defaultHandler.Load(); cur != nil && (*cur).Tag() == tag {
		m.defaultHandler.CompareAndSwap(cur, nil)
	}

	return nil
}

// ListHandlers implements outbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []outbound.Handler {
	var response []outbound.Handler
	if untagged := m.untaggedHandlers.Load(); untagged != nil {
		response = slices.Clone(*untagged)
	}

	m.taggedHandler.Range(func(_ string, v outbound.Handler) bool {
		response = append(response, v)
		return true
	})

	return response
}

// Select implements outbound.HandlerSelector.
func (m *Manager) Select(selectors []string) []string {
	key := strings.Join(selectors, ",")
	if result, ok := m.tagsCache.Load(key); ok {
		return result
	}

	tags := make([]string, 0, len(selectors))

	m.taggedHandler.Range(func(tag string, _ outbound.Handler) bool {
		for _, selector := range selectors {
			if strings.HasPrefix(tag, selector) {
				tags = append(tags, tag)
				break
			}
		}
		return true
	})

	sort.Strings(tags)
	m.tagsCache.Store(key, tags)

	return tags
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.OutboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.OutboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.OutboundHandlerConfig))
	}))
}
