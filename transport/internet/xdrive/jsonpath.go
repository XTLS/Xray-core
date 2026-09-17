package xdrive

import (
	"encoding/json"
	"strings"
)

func jsonWalk(payload []byte, path string) interface{} {
	var root interface{}
	if json.Unmarshal(payload, &root) != nil {
		return nil
	}
	node := root
	for _, key := range strings.Split(path, ".") {
		obj, ok := node.(map[string]interface{})
		if !ok {
			return nil
		}
		node, ok = obj[key]
		if !ok {
			return nil
		}
	}
	return node
}

func jsonString(payload []byte, path string) string {
	if s, ok := jsonWalk(payload, path).(string); ok {
		return s
	}
	return ""
}

func jsonNumber(payload []byte, path string) int64 {
	if f, ok := jsonWalk(payload, path).(float64); ok {
		return int64(f)
	}
	return 0
}
