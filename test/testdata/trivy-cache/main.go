// Builds a minimal Trivy vulnerability DB for the e2e tests.
//
// It copies npm advisories for the given packages from a full Trivy DB,
// along with the referenced vulnerability details, into db/trivy.db.
//
// Usage:
//
//	go run . <path to full trivy.db> <package>...
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var sources = []string{
	"npm::GitHub Security Advisory npm",
	"npm::Node.js Ecosystem Security Working Group",
}

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: go run . <path to full trivy.db> <package>...")
	}
	srcPath, pkgs := os.Args[1], os.Args[2:]
	dstPath := filepath.Join("db", "trivy.db")

	if err := os.Remove(dstPath); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	src, err := bolt.Open(srcPath, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		log.Fatal(err)
	}
	defer src.Close()

	dst, err := bolt.Open(dstPath, 0o644, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer dst.Close()

	err = src.View(func(stx *bolt.Tx) error {
		return dst.Update(func(dtx *bolt.Tx) error {
			return copyAdvisories(stx, dtx, pkgs)
		})
	})
	if err != nil {
		log.Fatal(err)
	}

	metadata, err := os.ReadFile(filepath.Join(filepath.Dir(srcPath), "metadata.json"))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("db", "metadata.json"), metadata, 0o644); err != nil {
		log.Fatal(err)
	}
}

func copyAdvisories(stx, dtx *bolt.Tx, pkgs []string) error {
	ids := map[string]struct{}{}

	for _, source := range sources {
		srcBucket := stx.Bucket([]byte(source))
		if srcBucket == nil {
			return fmt.Errorf("bucket %q not found", source)
		}
		dstBucket, err := dtx.CreateBucketIfNotExists([]byte(source))
		if err != nil {
			return err
		}

		for _, pkg := range pkgs {
			srcPkgBucket := srcBucket.Bucket([]byte(pkg))
			if srcPkgBucket == nil {
				continue
			}
			dstPkgBucket, err := dstBucket.CreateBucketIfNotExists([]byte(pkg))
			if err != nil {
				return err
			}
			err = srcPkgBucket.ForEach(func(id, advisory []byte) error {
				ids[string(id)] = struct{}{}
				return dstPkgBucket.Put(id, advisory)
			})
			if err != nil {
				return err
			}
		}

		if err := copyKey(stx, dtx, "data-source", source); err != nil {
			return err
		}
	}

	for id := range ids {
		if err := copyKey(stx, dtx, "vulnerability", id); err != nil {
			return err
		}
	}

	log.Printf("copied %d vulnerabilities", len(ids))
	return nil
}

func copyKey(stx, dtx *bolt.Tx, bucket, key string) error {
	value := stx.Bucket([]byte(bucket)).Get([]byte(key))
	if value == nil {
		return nil
	}
	dstBucket, err := dtx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	return dstBucket.Put([]byte(key), value)
}
