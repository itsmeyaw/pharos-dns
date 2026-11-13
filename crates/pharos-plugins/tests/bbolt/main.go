package main

import (
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

func main() {
	if len(os.Args) != 3 {
		panic("expected mode and path")
	}
	db, err := bolt.Open(os.Args[2], 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if os.Args[1] == "write" || os.Args[1] == "write-complex" {
		err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("dynupdate-v1"))
			if err != nil {
				return err
			}
			if err = b.Put([]byte("origin"), []byte("example.org.")); err != nil {
				return err
			}
			if os.Args[1] == "write-complex" {
				for i := 0; i < 256; i++ {
					name := fmt.Sprintf("extra-%04d", i)
					if err = b.Put([]byte(name), []byte("kept")); err != nil {
						return err
					}
					other, err := tx.CreateBucket([]byte(name))
					if err != nil {
						return err
					}
					if err = other.Put([]byte("key"), []byte("value")); err != nil {
						return err
					}
				}
			}
			return b.Put([]byte("records"), []byte("record data"))
		})
	} else {
		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("dynupdate-v1"))
			if b == nil {
				return fmt.Errorf("bucket missing")
			}
			if os.Args[1] == "verify-complex" {
				for i := 0; i < 256; i++ {
					name := fmt.Sprintf("extra-%04d", i)
					other := tx.Bucket([]byte(name))
					if string(b.Get([]byte(name))) != "kept" || other == nil || string(other.Get([]byte("key"))) != "value" {
						return fmt.Errorf("missing %s", name)
					}
				}
				for err := range tx.Check() {
					if err != nil {
						return err
					}
				}
			}
			fmt.Printf("%s\n%s\n", b.Get([]byte("origin")), b.Get([]byte("records")))
			return nil
		})
	}
	if err != nil {
		panic(err)
	}
}
