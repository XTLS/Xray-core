package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	// 使用 generated 目录下的 gRPC 客户端
	// 注意：由于生成的代码的 go_package 是 github.com/xtls/xray-core/app/...，
	// 我们需要通过 replace 指令让 Go 找到 generated 目录下的代码
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"

	// 使用主项目的 common 包（包含 ToTypedMessage 等工具函数）
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	serverAddr = flag.String("server", "127.0.0.1:8080", "gRPC server address")
	timeout    = flag.Duration("timeout", 5*time.Second, "Request timeout")
)

func main() {
	flag.Parse()

	// 连接到 gRPC 服务器
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to Xray gRPC server at %s\n\n", *serverAddr)

	// 示例 1: 使用 StatsService 获取统计信息
	demonstrateStatsService(ctx, conn)

	// 示例 2: 使用 HandlerService 列出 inbound
	demonstrateHandlerService(ctx, conn)
}

// demonstrateStatsService 展示如何使用 StatsService
func demonstrateStatsService(ctx context.Context, conn *grpc.ClientConn) {
	fmt.Println("=== StatsService Examples ===")

	statsClient := statsService.NewStatsServiceClient(conn)

	// 示例 1: 获取系统统计信息
	fmt.Println("\n1. Getting system stats...")
	sysStats, err := statsClient.GetSysStats(ctx, &statsService.SysStatsRequest{})
	if err != nil {
		log.Printf("Failed to get sys stats: %v", err)
	} else {
		fmt.Printf("   Uptime: %d seconds\n", sysStats.Uptime)
		fmt.Printf("   Goroutines: %d\n", sysStats.NumGoroutine)
		fmt.Printf("   Memory Alloc: %d bytes\n", sysStats.Alloc)
		fmt.Printf("   GC Count: %d\n", sysStats.NumGC)
	}

	// 示例 2: 查询统计信息（使用通配符）
	fmt.Println("\n2. Querying stats with pattern 'inbound>>>'...")
	queryResp, err := statsClient.QueryStats(ctx, &statsService.QueryStatsRequest{
		Pattern: "inbound>>>",
		Reset_:  false,
	})
	if err != nil {
		log.Printf("Failed to query stats: %v", err)
	} else {
		fmt.Printf("   Found %d stat(s):\n", len(queryResp.Stat))
		for i, stat := range queryResp.Stat {
			if i < 5 { // 只显示前 5 个
				fmt.Printf("   - %s: %d\n", stat.Name, stat.Value)
			}
		}
		if len(queryResp.Stat) > 5 {
			fmt.Printf("   ... and %d more\n", len(queryResp.Stat)-5)
		}
	}

	// 示例 3: 获取特定统计信息
	fmt.Println("\n3. Getting specific stat 'inbound>>>statin>>>traffic>>>downlink'...")
	statResp, err := statsClient.GetStats(ctx, &statsService.GetStatsRequest{
		Name:   "inbound>>>statin>>>traffic>>>downlink",
		Reset_: false,
	})
	if err != nil {
		log.Printf("Failed to get stats: %v (this is normal if the stat doesn't exist)", err)
	} else {
		fmt.Printf("   Stat: %s = %d\n", statResp.Stat.Name, statResp.Stat.Value)
	}
}

// demonstrateHandlerService 展示如何使用 HandlerService
func demonstrateHandlerService(ctx context.Context, conn *grpc.ClientConn) {
	fmt.Println("\n=== HandlerService Examples ===")

	handlerClient := handlerService.NewHandlerServiceClient(conn)

	// 示例 1: 列出所有 inbound
	fmt.Println("\n1. Listing all inbounds...")
	listResp, err := handlerClient.ListInbounds(ctx, &handlerService.ListInboundsRequest{
		IsOnlyTags: true,
	})
	if err != nil {
		log.Printf("Failed to list inbounds: %v", err)
	} else {
		fmt.Printf("   Found %d inbound(s):\n", len(listResp.Inbounds))
		for i, inbound := range listResp.Inbounds {
			if i < 10 { // 只显示前 10 个
				fmt.Printf("   - Tag: %s\n", inbound.Tag)
			}
		}
		if len(listResp.Inbounds) > 10 {
			fmt.Printf("   ... and %d more\n", len(listResp.Inbounds)-10)
		}
	}

	// 示例 2: 获取 inbound 的用户列表
	if len(listResp.Inbounds) > 0 {
		firstTag := listResp.Inbounds[0].Tag
		fmt.Printf("\n2. Getting users for inbound '%s'...\n", firstTag)
		usersResp, err := handlerClient.GetInboundUsers(ctx, &handlerService.GetInboundUserRequest{
			Tag: firstTag,
		})
		if err != nil {
			log.Printf("Failed to get inbound users: %v", err)
		} else {
			fmt.Printf("   Found %d user(s):\n", len(usersResp.Users))
			for i, user := range usersResp.Users {
				if i < 5 { // 只显示前 5 个
					fmt.Printf("   - Email: %s, Level: %d\n", user.Email, user.Level)
				}
			}
			if len(usersResp.Users) > 5 {
				fmt.Printf("   ... and %d more\n", len(usersResp.Users)-5)
			}
		}
	}

	// 示例 3: 添加用户（需要有效的 inbound tag）
	fmt.Println("\n3. Example: Adding a user (commented out to avoid errors)")
	fmt.Println("   To add a user, you would use:")
	fmt.Println("   handlerClient.AlterInbound(ctx, &handlerService.AlterInboundRequest{")
	fmt.Println("       Tag: \"your-inbound-tag\",")
	fmt.Println("       Operation: serial.ToTypedMessage(&handlerService.AddUserOperation{")
	fmt.Println("           User: createVMessUser(\"test@example.com\", \"your-uuid\"),")
	fmt.Println("       }),")
	fmt.Println("   })")

	// 示例 4: 列出所有 outbound
	fmt.Println("\n4. Listing all outbounds...")
	outboundResp, err := handlerClient.ListOutbounds(ctx, &handlerService.ListOutboundsRequest{})
	if err != nil {
		log.Printf("Failed to list outbounds: %v", err)
	} else {
		fmt.Printf("   Found %d outbound(s):\n", len(outboundResp.Outbounds))
		for i, outbound := range outboundResp.Outbounds {
			if i < 10 { // 只显示前 10 个
				fmt.Printf("   - Tag: %s\n", outbound.Tag)
			}
		}
		if len(outboundResp.Outbounds) > 10 {
			fmt.Printf("   ... and %d more\n", len(outboundResp.Outbounds)-10)
		}
	}
}

// createVMessUser 创建一个 VMess 用户（示例函数）
func createVMessUser(email, uuidStr string) *protocol.User {
	// 解析 UUID
	id, err := uuid.ParseString(uuidStr)
	if err != nil {
		// 如果解析失败，生成新的 UUID
		id = uuid.New()
	}

	// 创建 VMess 账户
	vmessAccount := &vmess.Account{
		Id: id.String(),
		SecuritySettings: &protocol.SecurityConfig{
			Type: protocol.SecurityType_AUTO,
		},
	}

	// 创建用户
	user := &protocol.User{
		Email:   email,
		Level:   0,
		Account: serial.ToTypedMessage(vmessAccount),
	}

	return user
}
