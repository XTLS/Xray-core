package monitor

import (
	. "github.com/amirdlt/flex/util"
	"time"
)

func init() {
	//NewPeriodicJob(func() {
	//	_, err := i.OnlineStatCol().DeleteMany(ctx, M{"last_connection": M{"$lte": time.Now().Add(-c.WindowSize)}})
	//	i.ReportIfErr(err)
	//
	//	ids, err := i.OnlineStatCol().Distinct(ctx, "_id", M{})
	//	ips := Stream[any](ids).MapToString(func(v any) string { return fmt.Sprint(v) })
	//
	//}, c.WindowSize).Start()

	NewPeriodicJob(func() {
		i.ReportInfo(len(goroutineCountLimiterSemaphore), "goroutine count limiter semaphore length")
	}, time.Minute)
}
