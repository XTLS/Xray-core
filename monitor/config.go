package monitor

import (
	"encoding/json"
	. "github.com/amirdlt/flex/util"
	"os"
)

type Config struct {
	Mongo struct {
		ConnectionString string `json:"connection_string"`
		DatabaseName     string `json:"database_name"`
	} `json:"mongo"`
}

var (
	useConfigFile = true

	c Config
)

func init() {
	var confBytes []byte
	var err error
	if useConfigFile {
		confBytes, _ = json.Marshal(M{
			"mongo": M{
				"connection_string": "mongodb://localhost:9213/",
				"database_name":     "xray_monitor",
			},
		})
	} else {
		confBytes, err = os.ReadFile("monitor_config.json")
		if err != nil {
			i.LogError(err, "could not load config file")
		}
	}

	if err := json.Unmarshal(confBytes, &c); err != nil {
		i.LogError(err, "could not unmarshal monitor config json file")
	}
}

func C() Config {
	return c
}
