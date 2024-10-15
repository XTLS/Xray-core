package monitor

import (
	. "github.com/amirdlt/flex/util"
	"time"
)

type Log struct {
	Level     string    `json:"level,omitempty" bson:"level,omitempty"`
	Message   string    `json:"message,omitempty" bson:"message,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	Error     string    `json:"error" bson:"error"`
	File      string    `json:"file" bson:"file"`
}

type Address struct {
	Query         string    `json:"query" bson:"_id"`
	Ip            string    `json:"ip,omitempty" bson:"ip,omitempty"`
	Status        string    `json:"status,omitempty" bson:"status"`
	Continent     string    `json:"continent,omitempty" bson:"continent,omitempty"`
	ContinentCode string    `json:"continentCode,omitempty" bson:"continentCode,omitempty"`
	Country       string    `json:"country,omitempty" bson:"country,omitempty"`
	CountryCode   string    `json:"countryCode,omitempty" bson:"countryCode,omitempty"`
	Region        string    `json:"region,omitempty" bson:"region,omitempty"`
	RegionName    string    `json:"regionName,omitempty" bson:"regionName,omitempty"`
	City          string    `json:"city,omitempty" bson:"city,omitempty"`
	District      string    `json:"district,omitempty" bson:"district,omitempty"`
	Zip           string    `json:"zip,omitempty" bson:"zip,omitempty"`
	Lat           float64   `json:"lat,omitempty" bson:"lat,omitempty"`
	Lon           float64   `json:"lon,omitempty" bson:"lon,omitempty"`
	Timezone      string    `json:"timezone,omitempty" bson:"timezone,omitempty"`
	Offset        int       `json:"offset,omitempty" bson:"offset,omitempty"`
	Currency      string    `json:"currency,omitempty" bson:"currency,omitempty"`
	ISP           string    `json:"isp,omitempty" bson:"isp,omitempty"`
	Org           string    `json:"org,omitempty" bson:"org,omitempty"`
	AS            string    `json:"as,omitempty" bson:"as,omitempty"`
	ASName        string    `json:"asname,omitempty" bson:"asname,omitempty"`
	Reverse       string    `json:"reverse,omitempty" bson:"reverse,omitempty"`
	Mobile        bool      `json:"mobile,omitempty" bson:"mobile,omitempty"`
	Proxy         bool      `json:"proxy,omitempty" bson:"proxy,omitempty"`
	Hosting       bool      `json:"hosting,omitempty" bson:"hosting,omitempty"`
	IsClient      bool      `json:"is_client" bson:"is_client"`
	IsServer      bool      `json:"is_server" bson:"is_server"`
	UpdatedAt     time.Time `json:"updated_at" bson:"updated_at"`
}

type CallStat struct {
	Count             uint64        `json:"count" bson:"count"`
	UploadByteCount   uint64        `json:"upload_byte_count" bson:"upload_byte_count"`
	DownloadByteCount uint64        `json:"download_byte_count" bson:"download_byte_count"`
	Duration          time.Duration `json:"duration" bson:"duration"`
}

type Window struct {
	Source           string                `json:"source" bson:"source"`
	Target           string                `json:"target" bson:"target"`
	StartTime        time.Time             `json:"start_time" bson:"start_time"`
	EndTime          time.Time             `json:"end_time" bson:"end_time"`
	Users            Map[string, CallStat] `json:"users" bson:"users"`
	DestinationPorts Stream[uint16]        `json:"destination_port" bson:"destination_port"`
	NetworkTypes     Stream[string]        `json:"network_types" bson:"network_types"`
}
