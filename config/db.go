package config

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

var (
	clientInstance *mongo.Client
	dbInstance     *mongo.Database
	dbName         = "Finger"
)

// GetMongoClient 返回单例 MongoClient
func GetMongoClient() *mongo.Client {
	return clientInstance
}

// GetMongoDB 返回单例 Mongo Database
func GetMongoDB() *mongo.Database {
	return dbInstance
}

// initMongo 保证只初始化一次（线程安全）
func initMongo() {
	uri, err := GetMongoUri()
	if err != nil {
		log.Println(err)
		return
	}
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clientOptions := options.Client().ApplyURI(uri)
		client, err := mongo.Connect(ctx, clientOptions)
		if err != nil {
			log.Fatalf("MongoDB 连接失败: %v", err)
		}
		if err := client.Ping(ctx, nil); err != nil {
			log.Fatalf("MongoDB Ping 失败: %v", err)
		}
		clientInstance = client
		dbInstance = client.Database(dbName)
		log.Println("MongoDB 单例初始化成功")
	})
}
