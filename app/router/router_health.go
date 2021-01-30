package router

import (
	"errors"
	"strings"

	"github.com/xtls/xray-core/features/routing"
)

// CheckHanlders implements routing.RouterChecker.
func (r *Router) CheckHanlders(tags []string) error {
	errs := make([]error, 0)
	for _, b := range r.balancers {
		checker, ok := b.strategy.(routing.HealthChecker)
		if !ok {
			continue
		}
		all, err := b.SelectOutbounds()
		if err != nil {
			return err
		}
		ts := getCheckTags(tags, all)
		err = checker.Check(ts)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return getCollectError(errs)
}

func getCheckTags(tags, all []string) []string {
	ts := make([]string, 0)
	for _, t := range tags {
		if findSliceIndex(all, t) >= 0 && findSliceIndex(ts, t) < 0 {
			ts = append(ts, t)
		}
	}
	return ts
}

// CheckBalancers implements routing.RouterChecker.
func (r *Router) CheckBalancers(tags []string) error {
	errs := make([]error, 0)
	for t, b := range r.balancers {
		if len(tags) > 0 && findSliceIndex(tags, t) < 0 {
			continue
		}
		checker, ok := b.strategy.(routing.HealthChecker)
		if !ok {
			continue
		}
		tags, err := b.SelectOutbounds()
		if err != nil {
			errs = append(errs, err)
		}
		err = checker.Check(tags)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return getCollectError(errs)
}

func getCollectError(errs []error) error {
	sb := new(strings.Builder)
	sb.WriteString("collect errors:\n")
	for _, err := range errs {
		sb.WriteString("    * ")
		sb.WriteString(err.Error())
		sb.WriteString("\n")
	}
	return errors.New(sb.String())
}

// GetBalancersInfo implements routing.RouterChecker.
func (r *Router) GetBalancersInfo(tags []string) (resp []*routing.BalancerInfo, err error) {
	resp = make([]*routing.BalancerInfo, 0)
	for t, b := range r.balancers {
		if len(tags) > 0 && findSliceIndex(tags, t) < 0 {
			continue
		}
		all, err := b.SelectOutbounds()
		if err != nil {
			return nil, err
		}
		var override *routing.BalancingOverrideInfo
		if o := b.override.Get(); o != nil {
			override = &routing.BalancingOverrideInfo{
				Until:   o.until,
				Selects: o.selects,
			}
		}
		stat := &routing.BalancerInfo{
			Tag:      t,
			Override: override,
			Strategy: b.strategy.GetInformation(all),
		}
		resp = append(resp, stat)
	}
	return resp, nil
}

func findSliceIndex(slice []string, find string) int {
	index := -1
	for i, v := range slice {
		if find == v {
			index = i
			break
		}
	}
	return index
}
