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
	Owner uint32
	Flag  uint32
	User  uint32
	Time  uint32

	Usage   uint32
	Allow   uint32
	Traffic uint32

	Trace   uint32
	Refresh uint32

	UserMap map[string]uint32
}

var AccountMapMutex = sync.Mutex{}
var AccountMap = make(map[string]*Account)

func init() {
	if Error != nil {
		panic(Error)
	}

	DB.SetConnMaxLifetime(time.Minute * 10)
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

		Cache.Trace += uint32(CounterUpload + CounterDownload)

		var UsageAsMB = Cache.Trace / 1000000

		if UsageAsMB > 0 {
			_, Error := DB.Exec("UPDATE `subscription` SET `Usage` = `Usage` + ? WHERE `UUID` = ? LIMIT 1", UsageAsMB, AccountKey)

			if Error != nil {
				fmt.Println(">> AccountUpdate-Traffic-Sub:", AccountKey, Error)

				return
			}

			_, Error = DB.Exec("UPDATE `account` SET `Traffic` = GREATEST(0, CAST(`Traffic` AS INT) - ?) WHERE `ID` = ? LIMIT 1", UsageAsMB, Cache.Owner)

			if Error != nil {
				fmt.Println(">> AccountUpdate-Traffic-Acc:", AccountKey, Error)

				return
			}

			Cache.Trace -= (UsageAsMB * 1000000)

			Cache.Usage += UsageAsMB
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

		Error := DB.QueryRow("SELECT `subscription`.`Owner`, `subscription`.`Flag`, `subscription`.`User`, `subscription`.`Time`, `subscription`.`Traffic`, `subscription`.`Usage`, `account`.`Traffic` AS `Allow` FROM `subscription` INNER JOIN `account` ON `subscription`.`Owner` = `account`.`ID` WHERE `UUID` = ? LIMIT 1;", AccountKey).Scan(&Cache.Owner, &Cache.Flag, &Cache.User, &Cache.Time, &Cache.Traffic, &Cache.Usage, &Cache.Allow)

		if Error != nil {
			fmt.Println(">> AccountVerify-Error-1:", AccountKey, Error)

			return false
		}

		Cache.Refresh = uint32(time.Now().Unix()) + 6

		Cache.UserMap = make(map[string]uint32)

		AccountMap[AccountKey] = Cache
	}

	if Cache.Refresh < uint32(time.Now().Unix()) {
		Error := DB.QueryRow("SELECT `subscription`.`Owner`, `subscription`.`Flag`, `subscription`.`User`, `subscription`.`Time`, `subscription`.`Traffic`, `subscription`.`Usage`, `account`.`Traffic` AS `Allow` FROM `subscription` INNER JOIN `account` ON `subscription`.`Owner` = `account`.`ID` WHERE `UUID` = ? LIMIT 1;", AccountKey).Scan(&Cache.Owner, &Cache.Flag, &Cache.User, &Cache.Time, &Cache.Traffic, &Cache.Usage, &Cache.Allow)

		if Error != nil {
			fmt.Println(">> AccountVerify-Error-2:", AccountKey, Error)

			return false
		}

		Cache.Refresh = uint32(time.Now().Unix()) + 6
	}

	if Cache.Flag > 0 {
		fmt.Println(">> AccountVerify-Flag:", AccountKey, Cache.Flag)

		return false
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

	if Cache.Traffic < Cache.Usage {
		fmt.Println(">> AccountVerify-Traffic:", AccountKey, Cache.Traffic, Cache.Usage)

		return false
	}

	if Cache.Allow < 750 {
		fmt.Println(">> AccountVerify-Allow:", AccountKey, Cache.Allow)

		return false
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

	return true
}
