package proxy

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/xtls/xray-core/common/uuid"
)

type Account struct {
	DownloadTrace uint32
	UploadTrace   uint32
	Download      uint32
	Traffic       uint32
	Upload        uint32
	Time          uint32
	User          uint32
	Flag          uint32
	Refresh       uint32
	UserMap       map[string]uint32
}

var AccountMapMutex = sync.Mutex{}
var AccountMap = make(map[string]*Account)

func init() {
	if Error != nil {
		panic(Error)
	}

	DB.SetConnMaxLifetime(time.Minute * 3)
	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(10)
}

func AccountUpdate(AccountUUID uuid.UUID, AccountIP net.Addr, CounterUpload int64, CounterDownload int64) {
	AccountMapMutex.Lock()
	defer AccountMapMutex.Unlock()

	var AccountKey = AccountUUID.String()

	Cache, OK := AccountMap[AccountKey]

	if OK {
		if Cache.User > 0 {
			IP := AccountIP.String()[:strings.Index(AccountIP.String(), ":")]

			IPCount, OK := Cache.UserMap[IP]

			if OK {
				if IPCount == 1 {
					delete(Cache.UserMap, IP)
				} else {
					Cache.UserMap[IP] = IPCount - 1
				}
			}
		}

		var Download = (Cache.DownloadTrace + uint32(CounterDownload)) / 1000000
		var Upload = (Cache.UploadTrace + uint32(CounterUpload)) / 1000000

		if Download > 1 || Upload > 1 {
			_, Error := DB.Exec("UPDATE `subscription` SET `Download` = `Download` + ?, `Upload` = `Upload` + ? WHERE `UUID` = ? LIMIT 1", Download, Upload, AccountKey)

			if Error != nil {
				fmt.Println(">> AccountUpdate-Traffic:", AccountKey, Error)

				return
			}

			Cache.DownloadTrace = (Cache.DownloadTrace + uint32(CounterDownload)) - (Download * 1000000)
			Cache.UploadTrace = (Cache.UploadTrace + uint32(CounterUpload)) - (Upload * 1000000)

			Cache.Download += Download
			Cache.Upload += Upload
		} else {
			Cache.DownloadTrace += uint32(CounterDownload)
			Cache.UploadTrace += uint32(CounterUpload)
		}
	}
}

func AccountVerify(AccountUUID uuid.UUID, AccountIP net.Addr) bool {
	AccountMapMutex.Lock()
	defer AccountMapMutex.Unlock()

	var AccountKey = AccountUUID.String()

	Cache, OK := AccountMap[AccountKey]

	if !OK {
		Cache = new(Account)

		QuerySelect := DB.QueryRow("SELECT `Flag`, `User`, `Time`, `Traffic`, `Upload`, `Download` FROM `subscription` WHERE `UUID` = ? LIMIT 1", AccountKey).Scan(&Cache.Flag, &Cache.User, &Cache.Time, &Cache.Traffic, &Cache.Upload, &Cache.Download)

		if QuerySelect != nil {
			fmt.Println(">> AccountVerify-Query-1:", AccountKey, QuerySelect)

			return false
		}

		Cache.Refresh = uint32(time.Now().Unix()) + 60

		Cache.UserMap = make(map[string]uint32)

		AccountMap[AccountKey] = Cache
	}

	if Cache.Refresh < uint32(time.Now().Unix()) {
		QuerySelect := DB.QueryRow("SELECT `Flag`, `User`, `Time`, `Traffic`, `Upload`, `Download` FROM `subscription` WHERE `UUID` = ? LIMIT 1", AccountKey).Scan(&Cache.Flag, &Cache.User, &Cache.Time, &Cache.Traffic, &Cache.Upload, &Cache.Download)

		if QuerySelect != nil {
			fmt.Println(">> AccountVerify-Query-2:", AccountKey, QuerySelect)

			return false
		}

		Cache.Refresh = uint32(time.Now().Unix()) + 60
	}

	if Cache.User > 0 {
		IP := AccountIP.String()[:strings.Index(AccountIP.String(), ":")]

		IPCount, OK := Cache.UserMap[IP]

		if !OK {
			if len(Cache.UserMap) >= int(Cache.User) {
				fmt.Println(">> AccountVerify-User:", len(Cache.UserMap), Cache.User)

				return false
			}

			IPCount = 0
		}

		Cache.UserMap[IP] = IPCount + 1
	}

	if Cache.Time > 0 {
		if Cache.Time < (5 * 365) {
			var Time = uint32(time.Now().Unix()) + (Cache.Time * 86400)

			_, Error := DB.Exec("UPDATE `subscription` SET `Time` = ? WHERE `UUID` = ? LIMIT 1", Time, AccountKey)

			if Error != nil {
				fmt.Println(">> AccountVerify-Time:", AccountKey, Error)

				return false
			}

			Cache.Time = Time
		} else if Cache.Time < uint32(time.Now().Unix()) {
			fmt.Println(">> AccountVerify-Time:", AccountKey, Cache.Time, uint32(time.Now().Unix()))

			return false
		}
	}

	if Cache.Traffic > 0 && (Cache.Traffic*1000) < (Cache.Upload+Cache.Download) {
		fmt.Println(">> AccountVerify-Traffic:", AccountKey, (Cache.Traffic * 1000), (Cache.Upload + Cache.Download))

		return false
	}

	if Cache.Flag > 0 {
		fmt.Println(">> AccountVerify-Flag:", AccountKey, Cache.Flag)

		return false
	}

	return true
}
