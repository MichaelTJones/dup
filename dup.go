package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"sync"
	"time"
	"walk"
)

//
// dup: Traverse directory hierarchies in search of duplicated files.
//      Author: Michael T. Jones 2-July-2014.

// I don't know why this was not an original UNIX shell tool, since it
// is generic and useful. Tries to be smart. Uses hash-tables for O(1)
// access. Hashes by file size, then by SHA-256 (configurable) on the
// first 4K bytes of the files, then on full files as needed. Options
// are few:

// COMPARE adds the extra step of byte-by-byte file comparison as the
// last resort in proving that two files are identical.
var compare = flag.Bool("c", false, "compare file bytes certainty")

// VERBOSE causes detailed summary statistics to be logged.
var verbose = flag.Bool("v", false, "verbose summary statistics")

type SizePair struct {
	size int64
	path string
}

func main() {
	t0 := time.Now()
	flag.Parse()

	// Part One: Build a map of file paths indexed by file size in bytes
	//
	// Only files of the same size could possibly be duplicates, so this
	// initial pass allows us to skip all the singleton files in the hash
	// computations of part two.

	var lock sync.Mutex
	var tFiles, tBytes int // total files and bytes
	sizeChan := make(chan SizePair, 1024)
	sizeDone := make(chan bool)
	sizeMap := make(map[int64][]string)
	go func() {
		for sp := range sizeChan {
			sizeMap[sp.size] = append(sizeMap[sp.size], sp.path)
		}
		sizeDone <- true
	}()

	sizeVisitor := func(path string, info os.FileInfo, err error) error {
		if err != nil || info.Mode()&os.ModeType != 0 {
			return nil // skip special files
		}
		if size := info.Size(); size > 0 { // skip empty files
			lock.Lock()
			tFiles++
			tBytes += int(size)
			lock.Unlock()
			// sizeMap[size] = append(sizeMap[size], path)
			sizeChan <- SizePair{size, path}
		}
		return nil
	}
	for _, p := range flag.Args() {
		// filepath.Walk(p, sizeVisitor)
		walk.Walk(p, sizeVisitor)

	}
	close(sizeChan)
	<-sizeDone

	// Part Two: Distinguish same-size files using hash codes and comparison.
	//
	// Try distinguishing using the first PREFIX bytes, which works on 80%
	// or more of the files, and then rehash using the full file as needed.
	// In '-c mode' files whose full-file checksums match are also compared
	// byte-by-byte, which allows the use of a weaker hash function with the
	// strong backing of full comparision for identicality.
	//
	// Runs as WORKERS + 2 concurrent activities. Set GOMAXPROCS in your
	// environment to at least the number of logical CPUs in your system.

	const workers = 8
	const prefix = 4 * 1024 // first 4K bytes catches most non-duplicates
	const done = -1

	// launch goroutines to process groups of same-size files
	in := make(chan Group, 256)  // may be buffered or unbuffered
	out := make(chan Group, 256) // may be buffered or unbuffered
	worker := func() {
		var hash Hash
		hashSlice := hash[:]
		for g := range in {
			// group files using prefix hash of each file
			dupPrefix := make(map[Hash][]string)
			for _, p := range g.path {
				hashFile(p, hashSlice, int64(prefix))
				dupPrefix[hash] = append(dupPrefix[hash], p)
			}

			switch {
			// small files already fully-hashed by prefix
			case g.size <= prefix:
				for _, path := range dupPrefix {
					if len(path) > 1 && (!*compare || identical(g.size, path)) {
						sort.Strings(path)
						out <- Group{g.size, path}
					}
				}
			// large files require a more thorough effort
			default:
				dupEntire := make(map[Hash][]string)
				for _, path := range dupPrefix {
					if len(path) > 1 {
						for _, p := range path {
							hashFile(p, hashSlice, 0) // entire file
							dupEntire[hash] = append(dupEntire[hash], p)
						}
					}
				}
				for _, path := range dupEntire {
					if len(path) > 1 && (!*compare || identical(g.size, path)) {
						sort.Strings(path)
						out <- Group{g.size, path} // large duplicates
					}
				}
			}
		}
		out <- Group{done, nil} // signal end of this worker
	}
	for i := 0; i < workers; i++ {
		go worker()
	}

	// launch collected same-size file groups as input to the expensive
	// hash-based (and comparison-based) file processing of the workers.
	var eFiles, eBytes int
	go func() {
		for size, path := range sizeMap {
			if len(path) > 1 {
				in <- Group{size, path}
				eFiles += len(path)
				eBytes += len(path) * int(size)
			}
		}
		close(in) // signals end of same-size groups
	}()

	// gather presumed to be duplicative groups from the workers
	var output Groups
	for active := workers; active > 0; {
		switch g := <-out; {
		case g.size == done:
			active-- // worker completion events sent through channel
		default:
			output = append(output, g)
		}
	}
	output.sort()
	𝛥t := float64(time.Now().Sub(t0)) / 1e9

	// print list of duplicated files
	var dFiles, dBytes int
	for i, g := range output {
		dFiles += len(g.path) // -1 to count redundancy
		dBytes += len(g.path) * int(g.size)
		for _, p := range g.path {
			fmt.Printf("  %12d %v\n", g.size, p)
		}
		if i < len(output)-1 {
			fmt.Printf("\n")
		}
	}

	// print optional verbose summary report
	if *verbose {
		log.Printf("     total: %8d files (%7.2f%%), %13d bytes (%7.2f%%)\n",
			tFiles, 100.0, tBytes, 100.0)

		efp := 100 * float64(eFiles) / float64(tFiles)
		ebp := 100 * float64(eBytes) / float64(tBytes)
		log.Printf("  examined: %8d files (%7.2f%%), %13d bytes (%7.2f%%) in %.4f seconds\n",
			eFiles, efp, eBytes, ebp, 𝛥t)

		dfp := 100 * float64(dFiles) / float64(tFiles)
		dbp := 100 * float64(dBytes) / float64(tBytes)
		log.Printf("duplicates: %8d files (%7.2f%%), %13d bytes (%7.2f%%)\n",
			dFiles, dfp, dBytes, dbp)
	}
}

// Compute hash summary for named file and return count of bytes read.
// Nominally uses SHA-256 but that is easily changed here and via the
// Hash type to something faster or stronger.

// type Hash [8]byte // appropriate for FNV-1a
// type Hash [16]byte // appropriate for MD5
type Hash [32]byte // appropriate for SHA-256
// type Hash [64]byte // appropriate for SHA-512

func hashFile(p string, hash []byte, prefix int64) (count int64) {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 1*1024)

	// hasher := fnv.New64a() // select FNV-1a in concert with "Hash" above
	// hasher := md5.New() // select MD5 in concert with "Hash" above
	hasher := sha256.New() // select SHA-256 in concert with "Hash" above
	// hasher := sha512.New() // select SHA-512 in concert with "Hash" above

	switch {
	case prefix == 0:
		count, _ = io.Copy(hasher, reader) // hash whole file
	default:
		count, _ = io.CopyN(hasher, reader, prefix) // hash prefix
	}
	copy(hash, hasher.Sum(nil))
	return
}

// Compare files for identicality as may appeal to the untrusting
func identical(size int64, path []string) bool {
	const buffer = 128 * 1024 // arbitrary
	if size <= buffer {
		a, err := ioutil.ReadFile(path[0])
		if err != nil {
			log.Printf("Error: %s\n", err)
			return false // skip this whole group if any errors happen
		}
		for i := 1; i < len(path); i++ {
			b, err := ioutil.ReadFile(path[i])
			if err != nil {
				log.Printf("Error: %s\n", err)
				return false // skip this whole group if any errors happen
			}
			if bytes.Compare(a, b) != 0 {
				log.Printf("Congratulations! You have found two files that differ(*), yet have\n")
				log.Printf("the same hash value. Publish these two files for a moment of fame:\n")
				log.Printf("    file %q\n", path[0])
				log.Printf("    file %q\n", path[i])
				log.Printf("* Or, the files were modified while this program was executing, in\n")
				log.Printf("  which case there is no fame to be had. Just run the program again.")
				return false
			}
		}
		return true
	} else {
		fa, err := os.Open(path[0])
		if err != nil {
			log.Printf("Error: %s\n", err)
			return false // skip this whole group if any errors happen
		}
		defer fa.Close()
		ra := bufio.NewReader(fa)

		ba := make([]byte, buffer)
		bb := make([]byte, buffer)

		for i := 1; i < len(path); i++ {
			// "rewind" file A
			fa.Seek(0, 0)

			fb, err := os.Open(path[i])
			if err != nil {
				log.Printf("Error: %s\n", err)
				return false // skip this whole group if any errors happen
			}
			rb := bufio.NewReader(fb)

			for {
				na, err := ra.Read(ba)
				if err != nil && err != io.EOF {
					fb.Close()
					log.Printf("Error: %s\n", err)
					return false // skip this whole group if any errors happen
				}
				nb, err := rb.Read(bb)
				if err != nil && err != io.EOF {
					fb.Close()
					log.Printf("Error: %s\n", err)
					return false // skip this whole group if any errors happen
				}
				if na == 0 && nb == 0 {
					fb.Close()
					break
				}
				if na != nb {
					fb.Close()
					log.Printf("Error: files are of differnt lengths!\n")
					return false // skip this whole group if any errors happen

				}
				if bytes.Compare(ba[:na], bb[:nb]) != 0 {
					fb.Close()
					log.Printf("Congratulations! You have found two files that differ(*), yet have\n")
					log.Printf("the same hash value. Publish these two files for a moment of fame:\n")
					log.Printf("    file %q\n", path[0])
					log.Printf("    file %q\n", path[i])
					log.Printf("* Or, the files were modified while this program was executing, in\n")
					log.Printf("  which case there is no fame to be had. Just run the program again.")
					return false
				}
			}
			return true
		}
	}
	return true
}

// The Group and Groups types describe groups of duplicate files

type Group struct {
	size int64    // size of each file in bytes
	path []string // full paths for each file
}
type Groups []Group // slice type for sorting

func (g Groups) Len() int      { return len(g) }
func (g Groups) Swap(i, j int) { g[i], g[j] = g[j], g[i] }
func (g Groups) Less(i, j int) bool {
	si := g[i].size
	sj := g[j].size
	return (si > sj) || (si == sj && g[i].path[0] < g[j].path[0]) // non-increasing size
}

func (group Groups) sort() {
	sort.Sort(group)
}
