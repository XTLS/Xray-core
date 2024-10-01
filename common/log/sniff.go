package log

// SniffLog is a log message when domain sniffed
// an implemention of log.Message
type SniffLog struct {
	OriginalDestination string
	Protocol            string
	Domain              string
}

func (l SniffLog) String() string {
	return "Destination " + l.OriginalDestination + " sniffed: " + l.Protocol + " -> " + l.Domain
}
