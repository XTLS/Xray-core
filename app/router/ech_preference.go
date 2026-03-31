package router

import (
	"context"

	"github.com/xtls/xray-core/features/extension"
)

func preferECHAcceptedCandidates(ctx context.Context, observer extension.Observatory, candidates []string) []string {
	provider, ok := observer.(extension.ECHStatusProvider)
	if !ok {
		return candidates
	}

	statuses, err := provider.GetOutboundECHStatus(ctx)
	if err != nil || len(statuses) == 0 {
		return candidates
	}

	preferred := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if status, ok := statuses[candidate]; ok && status.Accepted {
			preferred = append(preferred, candidate)
		}
	}
	if len(preferred) == 0 {
		return candidates
	}
	return preferred
}
