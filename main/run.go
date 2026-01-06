package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/common/errors"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRun = &base.Command{
	UsageLine: "{{.Exec}} run [-c config.json] [-confdir dir]",
	Short:     "Run Xray with config, the default command",
	Long: `
Run Xray with config, the default command.

The -config=file, -c=file flags set the config files for 
Xray. Multiple assign is accepted.

The -confdir=dir flag sets a dir with multiple json config

The -format=json flag sets the format of config files. 
Default "auto".

The -test flag tells Xray to test config files only, 
without launching the server.

The -dump flag tells Xray to print the merged config.
	`,
}

func init() {
	cmdRun.Run = executeRun // break init loop
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
}

var (
	configFiles cmdarg.Arg // "Config file for Xray.", the option is customed type, parse in main
	configDir   string
	dump        = cmdRun.Flag.Bool("dump", false, "Dump merged config only, without launching Xray server.")
	test        = cmdRun.Flag.Bool("test", false, "Test config file only, without launching Xray server.")
	format      = cmdRun.Flag.String("format", "auto", "Format of input file.")

	/* We have to do this here because Golang's Test will also need to parse flag, before
	 * main func in this file is run.
	 */
	_ = func() bool {
		cmdRun.Flag.Var(&configFiles, "config", "Config path for Xray.")
		cmdRun.Flag.Var(&configFiles, "c", "Short alias of -config")
		cmdRun.Flag.StringVar(&configDir, "confdir", "", "A dir with multiple json config")

		return true
	}()
)

func executeRun(cmd *base.Command, args []string) {
	if *dump {
		clog.ReplaceWithSeverityLogger(clog.Severity_Warning)
		errCode := dumpConfig()
		os.Exit(errCode)
	}

	printVersion()
	server, err := startXray()
	if err != nil {
		fmt.Println("Failed to start:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	if *test {
		fmt.Println("Configuration OK.")
		os.Exit(0)
	}

	if err := server.Start(); err != nil {
		fmt.Println("Failed to start:", err)
		os.Exit(-1)
	}
	defer server.Close()

	/*
		conf.FileCache = nil
		conf.IPCache = nil
		conf.SiteCache = nil
	*/

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	debug.FreeOSMemory()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func dumpConfig() int {
	files := getConfigFilePath(false)
	if config, err := core.GetMergedConfig(files); err != nil {
		fmt.Println(err)
		time.Sleep(1 * time.Second)
		return 23
	} else {
		fmt.Print(config)
	}
	return 0
}

func fileExists(file string) bool {
	info, err := os.Stat(file)
	return err == nil && !info.IsDir()
}

func dirExists(file string) bool {
	if file == "" {
		return false
	}
	info, err := os.Stat(file)
	return err == nil && info.IsDir()
}

func getRegepxByFormat() string {
	switch strings.ToLower(*format) {
	case "json":
		return `^.+\.(json|jsonc)$`
	case "toml":
		return `^.+\.toml$`
	case "yaml", "yml":
		return `^.+\.(yaml|yml)$`
	default:
		return `^.+\.(json|jsonc|toml|yaml|yml)$`
	}
}

func readConfDir(dirPath string) {
	confs, err := os.ReadDir(dirPath)
	if err != nil {
		log.Fatalln(err)
	}
	for _, f := range confs {
		matched, err := regexp.MatchString(getRegepxByFormat(), f.Name())
		if err != nil {
			log.Fatalln(err)
		}
		if matched {
			configFiles.Set(path.Join(dirPath, f.Name()))
		}
	}
}

func getConfigFilePath(verbose bool) cmdarg.Arg {
	if dirExists(configDir) {
		if verbose {
			log.Println("Using confdir from arg:", configDir)
		}
		readConfDir(configDir)
	} else if envConfDir := platform.GetConfDirPath(); dirExists(envConfDir) {
		if verbose {
			log.Println("Using confdir from env:", envConfDir)
		}
		readConfDir(envConfDir)
	}

	if len(configFiles) > 0 {
		return configFiles
	}

	if workingDir, err := os.Getwd(); err == nil {
		suffixes := []string{".json", ".jsonc", ".toml", ".yaml", ".yml"}
		for _, suffix := range suffixes {
			configFile := filepath.Join(workingDir, "config"+suffix)
			if fileExists(configFile) {
				if verbose {
					log.Println("Using default config: ", configFile)
				}
				return cmdarg.Arg{configFile}
			}
		}
	}

	if configFile := platform.GetConfigurationPath(); fileExists(configFile) {
		if verbose {
			log.Println("Using config from env: ", configFile)
		}
		return cmdarg.Arg{configFile}
	}

	if verbose {
		log.Println("Using config from STDIN")
	}
	return cmdarg.Arg{"stdin:"}
}

func getConfigFormat() string {
	f := core.GetFormatByExtension(*format)
	if f == "" {
		f = "auto"
	}
	return f
}

func startXray() (core.Server, error) {
	configFiles := getConfigFilePath(true)

	// config, err := core.LoadConfig(getConfigFormat(), configFiles[0], configFiles)

	c, err := core.LoadConfig(getConfigFormat(), configFiles)
	if err != nil {
		return nil, errors.New("failed to load config files: [", configFiles.String(), "]").Base(err)
	}

	server, err := core.New(c)
	if err != nil {
		return nil, errors.New("failed to create server").Base(err)
	}

	return server, nil
}
