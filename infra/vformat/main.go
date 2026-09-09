package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"mvdan.cc/gofumpt/format"
)

var (
	directory = flag.String("pwd", "", "Working directory of Xray vformat.")
	action    = flag.String("mode", "format", "Execution mode. Default is 'format'.\n'format' formatting source files and save changes to files.\n'check' list all paths of improper formatted file.\n'dryrun' formatting source files and shows all diffs, but will not make any changes to files.")
)

var (
	isCheck  bool
	isDryrun bool
	isFormat bool
)

func getModuleInfo(pwd string) (modPath, langVersion string, err error) {
	data, err := os.ReadFile(filepath.Join(pwd, "go.mod"))
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "module":
				modPath = fields[1]
			case "go":
				langVersion = "go" + strings.TrimPrefix(fields[1], "go")
			}
		}
	}
	return modPath, langVersion, nil
}

func formatGoSource(src []byte, opts format.Options) ([]byte, error) {
	return format.Source(src, opts)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of vformat:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if !filepath.IsAbs(*directory) {
		pwd, wdErr := os.Getwd()
		if wdErr != nil {
			fmt.Println("Can not get current working directory.")
			os.Exit(1)
		}
		*directory = filepath.Join(pwd, *directory)
	}

	switch *action {
	case "format":
		isFormat = true
	case "check":
		isCheck = true
	case "dryrun":
		isCheck = true
		isDryrun = true
	default:
		fmt.Println("Unrecognized 'mode'. Will format all source files and save changes.")
		isFormat = true
	}

	pwd := *directory
	modPath, langVersion, modErr := getModuleInfo(pwd)
	if modErr != nil {
		fmt.Println("Error reading go.mod:", modErr)
		os.Exit(1)
	}
	opts := format.Options{
		LangVersion: langVersion,
		ModulePath:  modPath,
	}

	if isFormat {
		fmt.Println("Formatting Go source files...")
	} else if isCheck {
		fmt.Println("Checking files thar are not properly formatted...")
	}

	jobs := make(chan string, runtime.NumCPU())
	var wg sync.WaitGroup
	var formatRequired atomic.Bool
	var hasErrors atomic.Bool

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Go(func() {
			for path := range jobs {
				src, err := os.ReadFile(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
					hasErrors.Store(true)
					continue
				}

				formatted, err := formatGoSource(src, opts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error formatting %s: %v\n", path, err)
					hasErrors.Store(true)
					continue
				}

				if !bytes.Equal(src, formatted) {
					var diffText []byte
					if isDryrun {
						newName := filepath.ToSlash(path)
						oldName := newName + ".orig"
						diffText = diff(oldName, src, newName, formatted)
					}
					if isFormat {
						info, statErr := os.Stat(path)
						if statErr != nil {
							fmt.Fprintf(os.Stderr, "Error stating %s: %v\n", path, statErr)
							hasErrors.Store(true)
							continue
						}
						if writeErr := os.WriteFile(path, formatted, info.Mode().Perm()); writeErr != nil {
							fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, writeErr)
							hasErrors.Store(true)
							continue
						}
					}

					formatRequired.Store(true)
					if isDryrun && len(diffText) > 0 {
						fmt.Printf("%s\n%s", path, diffText)
					} else {
						fmt.Println(path)
					}
				}
			}
		})
	}

	walkErr := filepath.Walk(pwd, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if info.IsDir() {
			return nil
		}

		dir := filepath.Dir(path)
		filename := filepath.Base(path)
		if strings.HasSuffix(filename, ".go") &&
			!strings.HasSuffix(filename, ".pb.go") &&
			!strings.Contains(dir, filepath.Join("testing", "mocks")) &&
			!strings.Contains(path, filepath.Join("main", "distro", "all", "all.go")) {
			jobs <- path
		}

		return nil
	})
	close(jobs)
	wg.Wait()

	if walkErr != nil {
		fmt.Println(walkErr)
		os.Exit(1)
	}

	if hasErrors.Load() {
		os.Exit(1)
	}

	if isFormat {
		if formatRequired.Load() {
			fmt.Println("Do NOT forget to commit file changes.")
		}
	}

	if isCheck {
		if formatRequired.Load() {
			fmt.Println("Format problem(s) found.")
			fmt.Println("Please run 'go run ./infra/vformat/main.go' to format the Go source files.")
			os.Exit(1)
		} else {
			fmt.Println("All Go source file format check has been passed.")
		}
	}
}

// diff algorithm copied from mvdan.cc/gofumpt/internal/govendor/diff
type pair struct{ x, y int }

func diff(oldName string, old []byte, newName string, new []byte) []byte {
	if bytes.Equal(old, new) {
		return nil
	}
	x := diffLines(old)
	y := diffLines(new)

	var out bytes.Buffer
	fmt.Fprintf(&out, "diff %s %s\n", oldName, newName)
	fmt.Fprintf(&out, "--- %s\n", oldName)
	fmt.Fprintf(&out, "+++ %s\n", newName)

	var (
		done  pair
		chunk pair
		count pair
		ctext []string
	)
	for _, m := range diffTgs(x, y) {
		if m.x < done.x {
			continue
		}
		start := m
		for start.x > done.x && start.y > done.y && x[start.x-1] == y[start.y-1] {
			start.x--
			start.y--
		}
		end := m
		for end.x < len(x) && end.y < len(y) && x[end.x] == y[end.y] {
			end.x++
			end.y++
		}

		for _, s := range x[done.x:start.x] {
			ctext = append(ctext, "-"+s)
			count.x++
		}
		for _, s := range y[done.y:start.y] {
			ctext = append(ctext, "+"+s)
			count.y++
		}

		const C = 3
		if (end.x < len(x) || end.y < len(y)) &&
			(end.x-start.x < C || (len(ctext) > 0 && end.x-start.x < 2*C)) {
			for _, s := range x[start.x:end.x] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}
			done = end
			continue
		}

		if len(ctext) > 0 {
			n := end.x - start.x
			if n > C {
				n = C
			}
			for _, s := range x[start.x : start.x+n] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}
			done = pair{start.x + n, start.y + n}

			if count.x > 0 {
				chunk.x++
			}
			if count.y > 0 {
				chunk.y++
			}
			fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", chunk.x, count.x, chunk.y, count.y)
			for _, s := range ctext {
				out.WriteString(s)
			}
			count.x = 0
			count.y = 0
			ctext = ctext[:0]
		}

		if end.x >= len(x) && end.y >= len(y) {
			break
		}

		chunk = pair{end.x - C, end.y - C}
		for _, s := range x[chunk.x:end.x] {
			ctext = append(ctext, " "+s)
			count.x++
			count.y++
		}
		done = end
	}

	return out.Bytes()
}

func diffLines(x []byte) []string {
	l := strings.SplitAfter(string(x), "\n")
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	} else {
		l[len(l)-1] += "\n\\ No newline at end of file\n"
	}
	return l
}

func diffTgs(x, y []string) []pair {
	m := make(map[string]int)
	for _, s := range x {
		if c := m[s]; c > -2 {
			m[s] = c - 1
		}
	}
	for _, s := range y {
		if c := m[s]; c > -8 {
			m[s] = c - 4
		}
	}

	var xi, yi, inv []int
	for i, s := range y {
		if m[s] == -5 {
			m[s] = len(yi)
			yi = append(yi, i)
		}
	}
	for i, s := range x {
		if j, ok := m[s]; ok && j >= 0 {
			xi = append(xi, i)
			inv = append(inv, j)
		}
	}

	J := inv
	n := len(xi)
	T := make([]int, n)
	L := make([]int, n)
	for i := range T {
		T[i] = n + 1
	}
	for i := 0; i < n; i++ {
		k := sort.Search(n, func(k int) bool {
			return T[k] >= J[i]
		})
		T[k] = J[i]
		L[i] = k + 1
	}
	k := 0
	for _, v := range L {
		if k < v {
			k = v
		}
	}
	seq := make([]pair, 2+k)
	seq[1+k] = pair{len(x), len(y)}
	lastj := n
	for i := n - 1; i >= 0; i-- {
		if L[i] == k && J[i] < lastj {
			seq[k] = pair{xi[i], yi[J[i]]}
			k--
		}
	}
	seq[0] = pair{0, 0}
	return seq
}
