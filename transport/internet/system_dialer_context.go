package internet

import "context"

type systemDialer int

const systemDialerKey systemDialer = 0

func ContextWithLookupDomain(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, systemDialerKey, domain)
}

func LookupDomainFromContext(ctx context.Context) string {
	if domain, ok := ctx.Value(systemDialerKey).(string); ok {
		return domain
	}
	return ""
}
