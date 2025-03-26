package router

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	route "github.com/xtls/xray-core/common/route"
)

// RestrictionRule implements routing.Router.
func (r *Router) RestrictionRule(restriction *route.Restriction, ip net.IP) error {

	mask := uint32(128)
	if ip.To4() != nil {
		mask = 32
	}

	cidrList := []*CIDR{{Ip: ip, Prefix: mask}}
	sourceIP := &GeoIP{Cidr: cidrList}

	// If rule exists, process it
	if r.RuleExists(restriction.Tag) {
		for _, rule := range r.rules {
			if rule.RuleTag == restriction.Tag {
				if shouldCleanup(restriction) {
					errors.LogWarning(r.ctx, "restriction cleanup -> ", restriction.Tag, " after ", restriction.CleanInterval, " seconds")
					restriction.LastCleanup = time.Now().Unix()
					return r.RemoveRule(restriction.Tag)
				}

				// If cleanup is not running, schedule it
				scheduleCleanup(r, restriction)

				// Check if IP already exists in the list
				if ipExistsInRestriction(rule.RoutingRule.SourceGeoip, cidrList[0]) {
					return errors.New(ip.String(), " already exists in restriction list.")
				}

				rule.RoutingRule.SourceGeoip = append(rule.RoutingRule.SourceGeoip, sourceIP)
				r.RemoveRule(restriction.Tag)
				return r.ReloadRules(&Config{Rule: []*RoutingRule{rule.RoutingRule}}, true, restriction.CleanInterval == 0)
			}
		}
	}

	// If rule does not exist, create a new one
	newRule := &RoutingRule{
		RuleTag:     restriction.Tag,
		TargetTag:   &RoutingRule_Tag{Tag: restriction.OutboundTag},
		SourceGeoip: []*GeoIP{sourceIP},
	}

	errors.LogWarning(r.ctx, "restrict IP -> ", ip.String(), " for route violation.")
	return r.ReloadRules(&Config{Rule: []*RoutingRule{newRule}}, true, restriction.CleanInterval == 0)
}

func shouldCleanup(restriction *route.Restriction) bool {
	return time.Now().Unix()-restriction.LastCleanup >= restriction.CleanInterval && restriction.LastCleanup != 0
}

func scheduleCleanup(r *Router, restriction *route.Restriction) {
	if !r.isCleanupRunning && restriction.CleanInterval != 0 {
		r.isCleanupRunning = true
		restriction.LastCleanup = time.Now().Unix()

		go time.AfterFunc(time.Duration(restriction.CleanInterval)*time.Second, func() {
			r.RestrictionRule(restriction, nil)
			r.isCleanupRunning = false
		})
	}
}

func ipExistsInRestriction(sourceGeoip []*GeoIP, newCIDR *CIDR) bool {
	for _, source := range sourceGeoip {
		for _, cidr := range source.GetCidr() {
			if string(cidr.GetIp()) == string(newCIDR.GetIp()) {
				return true
			}
		}
	}
	return false
}
