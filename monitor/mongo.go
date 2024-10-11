package monitor

import (
	"github.com/amirdlt/flex/db/mongo"
)

var (
	DestinationCol *mongo.Collection
	LogCol         *mongo.Collection
)

func init() {
	s.SetDefaultMongoClient(c.Mongo.ConnectionString)
	db := s.GetMongoClient("").GetDatabase(c.Mongo.DatabaseName)

	DestinationCol = db.GetCollection("destination")
	LogCol = db.GetCollection("log")
}
