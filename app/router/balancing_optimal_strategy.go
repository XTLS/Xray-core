package router

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type TagWeight struct {
	tag    string
	weight float64
}

// OptimalStrategy pick outbound by net speed
type OptimalStrategy struct {
	timeout            time.Duration
	interval           time.Duration
	url                *url.URL
	count              uint32
	acceptLittleDiff   bool
	diffPercent        float64
	loadBalancing      bool
	obm                outbound.Manager
	tag                string
	tags               []string
	acceptableTags     []string
	weights            map[string]uint32
	periodic           *task.Periodic
	periodicMutex      sync.Mutex
	loadBalancingMutex sync.Mutex
	ctx                context.Context
}

// NewOptimalStrategy creates a new OptimalStrategy
func NewOptimalStrategy(config *BalancingOptimalStrategyConfig) *OptimalStrategy {
	s := &OptimalStrategy{}

	if config.Timeout == 0 {
		s.timeout = time.Second * 5
	} else {
		s.timeout = time.Millisecond * time.Duration(config.Timeout)
	}

	if config.Interval == 0 {
		s.interval = time.Second * 60 * 10
	} else {
		s.interval = time.Millisecond * time.Duration(config.Interval)
	}

	if config.Url == "" {
		s.url, _ = url.Parse("https://www.google.com")
	} else {
		var err error
		s.url, err = url.Parse(config.Url)
		if err != nil {
			panic(err)
		}

		if s.url.Scheme != "http" && s.url.Scheme != "https" {
			panic("Only http/https urls are supported")
		}
	}

	if config.Count == 0 {
		s.count = 1
	} else {
		s.count = config.Count
	}

	s.weights = make(map[string]uint32)

	if config.Weights != nil {
		for _, w := range config.Weights {
			s.weights[w.Tag] = w.Weight
		}
	}

	if config.AcceptLittleDiff {

		s.acceptLittleDiff = true
		s.loadBalancing = config.LoadBalancing

		if config.DiffPercent == float64(0) {
			s.diffPercent = float64(90.0)
		} else {
			s.diffPercent = config.DiffPercent
		}
	} else {
		s.acceptLittleDiff = false
	}

	return s
}

func (s *OptimalStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
}

// PickOutbound implements BalancingStrategy interface
func (s *OptimalStrategy) PickOutbound(tags []string) string {
	if len(tags) == 0 {
		panic("0 tags")
	} else if len(tags) == 1 {
		return s.tag
	}

	if s.obm == nil {
		common.Must(core.RequireFeatures(s.ctx, func(ohm outbound.Manager) error {
			s.obm = ohm
			return nil
		}))
	}

	s.tags = tags

	if s.periodic == nil {
		s.periodicMutex.Lock()

		if s.periodic == nil {

			if s.acceptLittleDiff && s.loadBalancing {
				s.loadBalancingMutex.Lock()
				s.acceptableTags = nil
				s.acceptableTags = append(s.acceptableTags, s.tags[0])
				s.loadBalancingMutex.Unlock()
			} else {
				s.tag = s.tags[0]
			}

			s.periodic = &task.Periodic{
				Interval: s.interval,
				Execute:  s.run,
			}

			go s.periodic.Start()

		}

		s.periodicMutex.Unlock()
	}

	if s.acceptLittleDiff && s.loadBalancing {
		bestTag := s.getBestTag()
		return bestTag
	} else {
		return s.tag
	}
}

func (s *OptimalStrategy) getBestTag() string {
	s.loadBalancingMutex.Lock()
	defer s.loadBalancingMutex.Unlock()
	return s.acceptableTags[dice.Roll(len(s.acceptableTags))]
}

type optimalStrategyTestResult struct {
	tag   string
	score float64
}

// periodic execute function
func (s *OptimalStrategy) run() error {
	tags := s.tags
	count := s.count

	results := make([]optimalStrategyTestResult, len(tags))

	var wg sync.WaitGroup
	wg.Add(len(tags))
	for i, tag := range tags {
		result := &results[i]
		result.tag = tag
		go s.testOutbound(tag, result, count, &wg)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		// sort scores in desc order
		return results[i].score > results[j].score
	})

	if s.acceptLittleDiff {
		highestScore := results[0]
		acceptableScore := highestScore.score - highestScore.score*s.diffPercent
		acceptableResults := make([]optimalStrategyTestResult, 0)

		acceptableResults = append(acceptableResults, results[0])

		for idx, res := range results {
			if idx != 0 && res.score != 0 && res.score >= acceptableScore {
				acceptableResults = append(acceptableResults, res)
			}
		}

		if s.loadBalancing {
			s.loadBalancingMutex.Lock()
			previousAcceptableTags := s.acceptableTags
			s.acceptableTags = nil
			for _, aresult := range acceptableResults {
				s.acceptableTags = append(s.acceptableTags, aresult.tag)
			}
			newError(fmt.Sprintf("The balanced optimal strategy changes balancer outbounds from %s to %s", previousAcceptableTags, s.acceptableTags)).AtWarning().WriteToLog()
			s.loadBalancingMutex.Unlock()
		} else {

			var currentOutboundScore optimalStrategyTestResult

			for _, result := range results {
				if result.tag == s.tag {
					currentOutboundScore = result
				}
			}

			if &currentOutboundScore != nil && currentOutboundScore.score >= acceptableScore {
				return nil
			} else {
				randomlyChosenResult := acceptableResults[dice.Roll(len(acceptableResults))]
				if randomlyChosenResult.tag != s.tag {
					newError(fmt.Sprintf("The balanced optimal strategy changes outbound from [%s] to [%s] in %s", s.tag, results[0].tag, s.tags)).AtWarning().WriteToLog()
					s.tag = results[0].tag
				}
			}
		}

	} else {
		if results[0].tag != s.tag {
			newError(fmt.Sprintf("The balanced optimal strategy changes outbound from [%s] to [%s] in %s", s.tag, results[0].tag, s.tags)).AtWarning().WriteToLog()
			s.tag = results[0].tag
		}
	}

	return nil
}

// Test outbound's network state with multi-round
func (s *OptimalStrategy) testOutbound(tag string, result *optimalStrategyTestResult, count uint32, wg *sync.WaitGroup) {
	// test outbound by fetch url
	defer wg.Done()
	newError(fmt.Sprintf("s.obm.GetHandler %s", tag)).AtDebug().WriteToLog()
	oh := s.obm.GetHandler(tag)

	if oh == nil {
		newError("Wrong OptimalStrategy tag").AtError().WriteToLog()
		return
	}

	scores := make([]float64, count)
	for i := uint32(0); i < count; i++ {
		client := s.buildClient(oh)
		// send http request through this outbound
		req, _ := http.NewRequest("GET", s.url.String(), nil)
		startAt := time.Now()
		resp, err := client.Do(req)
		// use http response speed or time(no http content) as score
		score := 0.0
		if err != nil {
			newError(fmt.Sprintf("Balance OptimalStrategy tag %s error: %s", tag, err)).AtInfo().WriteToLog()
		} else {
			defer resp.Body.Close()
			bodyBuff := new(bytes.Buffer)
			contentSize, err := bodyBuff.ReadFrom(resp.Body)
			if err != nil {
				newError(fmt.Sprintf("Balance OptimalStrategy tag %s error: %s", tag, err)).AtInfo().WriteToLog()
			} else {
				finishAt := time.Now()
				useTime := float64(finishAt.UnixNano()-startAt.UnixNano()) / float64(time.Second)
				newError(fmt.Sprintf("Balance OptimalStrategy tag %s get contentSize: %d", tag, contentSize)).AtDebug().WriteToLog()
				newError(fmt.Sprintf("Balance OptimalStrategy tag %s useTime: %f", tag, useTime)).AtDebug().WriteToLog()

				var weight uint32 = 100.00
				if _, found := s.weights[tag]; found {
					weight = s.weights[tag]
				}

				if contentSize != 0 {
					score = float64(weight) * float64(contentSize) / useTime
				} else {
					// assert http header's byte size is 100B
					score = float64(weight) * 100 / useTime
				}
			}
		}

		scores[i] = score
		// next test round
		client.CloseIdleConnections()
	}

	// calculate average test score and end test round
	var minScore float64 = float64(math.MaxInt64)
	var maxScore float64 = float64(math.MinInt64)
	var sumScore float64
	var score float64

	for _, score := range scores {
		if score < minScore {
			minScore = score
		}

		if score > maxScore {
			maxScore = score
		}

		sumScore += score
	}

	if len(scores) < 3 {
		score = sumScore / float64(len(scores))
	} else {
		score = (sumScore - minScore - maxScore) / float64(s.count-2)
	}

	newError(fmt.Sprintf("Balance OptimalStrategy get %s 's score: %.2f", tag, score)).AtDebug().WriteToLog()
	result.score = score
}

func (s *OptimalStrategy) buildClient(oh outbound.Handler) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				netDestination, err := net.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
				if err != nil {
					return nil, err
				}

				uplinkReader, uplinkWriter := pipe.New()
				downlinkReader, downlinkWriter := pipe.New()

				ctx = session.ContextWithOutbound(
					ctx,
					&session.Outbound{
						Target: netDestination,
					})
				go oh.Dispatch(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter})

				return cnc.NewConnection(cnc.ConnectionInputMulti(uplinkWriter),
					cnc.ConnectionOutputMulti(downlinkReader)), nil
			},
			MaxIdleConnsPerHost: 1,
			MaxIdleConns:        1,
			DisableCompression:  true,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
		},
		Timeout: s.timeout,
	}
}
