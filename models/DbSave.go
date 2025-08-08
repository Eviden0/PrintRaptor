package models

import (
	"PrintRaptor/config"
	"context"
	"log"
	"time"
)

type DbSave struct {
	Banner *Banner
}

func (d *DbSave) Save() error {
	db := config.GetMongoDB()
	collection := db.Collection("banners")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, map[string]interface{}{
		"Host":       d.Banner.ResponseData.Host,
		"Title":      d.Banner.ResponseData.Title,
		"Hash":       d.Banner.ResponseData.Hash,
		"ICP":        d.Banner.ResponseData.ICP,
		"BodyLength": d.Banner.ResponseData.BodyLength,
		"Expression": d.Banner.CompiledRule.Expression,
		"RuleName":   d.Banner.CompiledRule.Name,
		"Rank":       d.Banner.CompiledRule.Rank,
	})
	if err != nil {
		log.Printf("写入MongoDB失败: %v", err)
		return err
	}
	log.Printf("成功写入MongoDB: %s", d.Banner.ResponseData.Host)
	return nil
}
func CloseMongoClient() {
	client := config.GetMongoClient()
	if client != nil {
		client.Disconnect(context.Background())
		log.Println("MongoDB 实例释放完毕")
	}
}
