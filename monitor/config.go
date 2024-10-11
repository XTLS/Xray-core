package monitor

import (
	"encoding/json"
	"os"
)

type Config struct {
	Mongo struct {
		ConnectionString string `json:"connection_string"`
		DatabaseName     string `json:"database_name"`
	} `json:"mongo"`
}

var c Config

func init() {
	confBytes, err := os.ReadFile("monitor_config.json")
	if err != nil {
		i.LogError(err, "could not load config file")
	}

	if err := json.Unmarshal(confBytes, &c); err != nil {
		i.LogError(err, "could not unmarshal monitor config json file")
	}
}

func C() Config {
	return c
}
