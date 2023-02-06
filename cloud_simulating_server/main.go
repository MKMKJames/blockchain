package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type StorageService struct {
	db     *leveldb.DB
	server *gin.Engine
}

func getStorageService(path string, opt *opt.Options) *StorageService {
	db, err := leveldb.OpenFile(path, opt)
	if err != nil {
		panic(err)
	}
	return &StorageService{db: db, server: gin.Default()}
}

func (s *StorageService) put(k, v string) {
	err := s.db.Put([]byte(k), []byte(v), nil)
	if err != nil {
		panic(err)
	}
}

func (s *StorageService) run(addr string) {
	s.server.Run(addr)
}

func (s *StorageService) close() {
	s.db.Close()
}

func (s *StorageService) get(k string) (string, error) {
	data, err := s.db.Get([]byte(k), nil)
	if err == leveldb.ErrNotFound {
		return "", err
	} else if err != nil {
		panic(err)
	}
	return string(data), nil
}

func (s *StorageService) setupRouter() {
	// Ping test
	s.server.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	// Get user value
	s.server.GET("/get/:key", func(c *gin.Context) {
		key := c.Params.ByName("key")
		value, err := s.get(key)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{"value": value})
		} else {
			c.JSON(http.StatusNotFound, gin.H{"cause": "No such key"})
		}
	})

	s.server.POST("put", func(c *gin.Context) {
		key := c.PostForm("key")
		value := c.PostForm("value")
		s.put(key, value)
		c.JSON(http.StatusOK, nil)
	})
}

func main() {
	service := getStorageService("./db", nil)
	service.setupRouter()
	service.server.Run(":8080")
	service.close()
}
