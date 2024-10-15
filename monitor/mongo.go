package monitor

import (
	"github.com/amirdlt/flex/db/mongo"
)

var (
	windowCol  *mongo.Collection
	addressCol *mongo.Collection

	logCol *mongo.Collection
)

func init() {
	s.SetDefaultMongoClient(c.Mongo.ConnectionString)
	db := s.GetMongoClient("").GetDatabase(c.Mongo.DatabaseName)

	windowCol = db.GetCollection("window")
	addressCol = db.GetCollection("address")
	logCol = db.GetCollection("log")
}
