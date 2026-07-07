//go:build windows
// +build windows

package all

import (
	"flag"
	"fmt"
	"syscall"

	"github.com/xtls/xray-core/main/commands/base"
	"golang.org/x/sys/windows/registry"
)

var cmdSysproxy = &base.Command{
	UsageLine: "{{.Exec}} sysproxy [-set server:port] [-bypass domains] [-clear]",
	Short:     "Manage Windows system proxy",
	Long: `Manage Windows system proxy settings natively.

Arguments:
	-set     Set the system proxy server (e.g., 127.0.0.1:10808)
	-bypass  Set the proxy bypass list (e.g., "localhost;127.*;10.*")
	-clear   Clear the system proxy and disable it
`,
}

func init() {
	cmdSysproxy.Run = executeSysproxy
	base.RootCommand.Commands = append(base.RootCommand.Commands, cmdSysproxy)
}

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

var (
	wininet            = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func notifyInternetSettingsChanged() {
	internetSetOptionW.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	internetSetOptionW.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}

func executeSysproxy(cmd *base.Command, args []string) {
	fs := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	setPtr := fs.String("set", "", "Proxy server to set (e.g., 127.0.0.1:10808)")
	bypassPtr := fs.String("bypass", "", "Proxy bypass list")
	clearPtr := fs.Bool("clear", false, "Clear system proxy")

	if err := fs.Parse(args); err != nil {
		fmt.Println(err)
		return
	}

	if *clearPtr {
		clearSysproxy()
		return
	}

	if *setPtr != "" {
		setSysproxy(*setPtr, *bypassPtr)
		return
	}

	fmt.Println("Usage:")
	fmt.Println(cmd.Long)
}

func setSysproxy(server, bypass string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("Failed to open registry key: %v\n", err)
		return
	}
	defer k.Close()

	err = k.SetDWordValue("ProxyEnable", 1)
	if err != nil {
		fmt.Printf("Failed to set ProxyEnable: %v\n", err)
		return
	}

	err = k.SetStringValue("ProxyServer", server)
	if err != nil {
		fmt.Printf("Failed to set ProxyServer: %v\n", err)
		return
	}

	if bypass != "" {
		err = k.SetStringValue("ProxyOverride", bypass)
		if err != nil {
			fmt.Printf("Failed to set ProxyOverride: %v\n", err)
			return
		}
	} else {
		_ = k.DeleteValue("ProxyOverride")
	}

	notifyInternetSettingsChanged()
	fmt.Printf("System proxy set to %s\n", server)
}

func clearSysproxy() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("Failed to open registry key: %v\n", err)
		return
	}
	defer k.Close()

	err = k.SetDWordValue("ProxyEnable", 0)
	if err != nil {
		fmt.Printf("Failed to disable ProxyEnable: %v\n", err)
		return
	}

	notifyInternetSettingsChanged()
	fmt.Println("System proxy cleared.")
}
