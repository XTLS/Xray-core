package geodata

import (
	"context"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	commongeodata "github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

type Instance struct {
	assets     []*Asset
	downloader *downloader
	tasker     *cron.Cron
	schedule   cron.Schedule
	job        cron.Job

	mu      sync.Mutex
	wg      sync.WaitGroup
	running bool
}

func New(ctx context.Context, config *Config) (*Instance, error) {
	if config.Cron == "" {
		return &Instance{}, nil
	}

	g := &Instance{
		assets: config.Assets,
	}

	if len(g.assets) > 0 {
		var dispatcher routing.Dispatcher
		if err := core.RequireFeatures(ctx, func(d routing.Dispatcher) {
			dispatcher = d
		}); err != nil {
			return nil, errors.New("failed to get dispatcher for geodata downloader").Base(err)
		}
		g.downloader = newDownloader(ctx, dispatcher, config.Outbound)
	}

	schedule, err := cron.ParseStandard(config.Cron)
	if err != nil {
		return nil, errors.New("invalid geodata cron").Base(err)
	}
	g.schedule = schedule
	g.job = cron.NewChain(cron.SkipIfStillRunning(cron.DiscardLogger)).Then(cron.FuncJob(g.execute))
	g.tasker = cron.New(cron.WithLogger(cron.DiscardLogger))
	g.tasker.Schedule(g.schedule, g.job)
	errors.LogInfo(ctx, "scheduled geodata reload with cron: ", config.Cron)

	return g, nil
}

func (g *Instance) execute() {
	var err error
	if g.downloader != nil {
		err = g.reloadWithUpdate()
	} else {
		err = reload()
	}
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "scheduled geodata reload failed")
	}
}

func (g *Instance) reloadWithUpdate() error {
	staged, err := g.downloader.download(g.assets)
	if err != nil {
		return err
	}
	defer clean(staged)

	tx, err := swapAll(staged)
	if err != nil {
		return err
	}

	if err := reload(); err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to reload geodata after downloading assets, rolling back")
		rollbackErr := tx.rollback()
		return errors.Combine(err, rollbackErr)
	}

	return tx.commit()
}

func reload() error {
	return errors.Combine(commongeodata.IPReg.Reload(), commongeodata.DomainReg.Reload())
}

func (g *Instance) shouldUpdate(now time.Time) bool {
	if g.schedule == nil || g.downloader == nil {
		return false
	}
	for _, asset := range g.assets {
		info, err := filesystem.StatAsset(asset.File)
		if err == nil && !g.schedule.Next(info.ModTime()).After(now) {
			return true
		}
	}
	return false
}

func (g *Instance) Type() interface{} {
	return (*Instance)(nil)
}

func (g *Instance) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.running {
		return nil
	}

	if g.tasker != nil {
		g.tasker.Start()
		if g.shouldUpdate(time.Now()) {
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				g.job.Run()
			}()
		}
	}

	g.running = true

	return nil
}

func (g *Instance) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return nil
	}

	if g.tasker != nil {
		<-g.tasker.Stop().Done()
	}
	g.wg.Wait()

	g.running = false

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*Config))
	}))
}
