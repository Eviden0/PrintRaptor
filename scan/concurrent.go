package scan

import (
	"PrintRaptor/fingerprints"
	"PrintRaptor/models"
	"log"
	"net/url"
	"sync"
)

func concurrent(targetsU []*url.URL, rules []fingerprints.CompiledRule, savaType uint8) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // 最多100个并发
	for _, targetUrl := range targetsU {
		for _, rule := range rules {
			wg.Add(1)
			sem <- struct{}{}
			go func(targetUrl *url.URL, rule fingerprints.CompiledRule) {
				defer wg.Done()
				defer func() { <-sem }()
				target, err := NewTarget(targetUrl, &rule)
				if err != nil {
					log.Printf("Error creating target for %s with rule %s: %v", targetUrl, rule.Name, err)
					return
				}
				banner, err := target.Request()
				if err != nil {
					return
				}
				if banner.Match() {
					result := &models.Result{
						Banner:   banner,
						SaveType: savaType,
					}
					err := result.GetSaver().Save()
					if err != nil {
						log.Printf("Error saving result for %s: %v", targetUrl, err)
					}
				}
			}(targetUrl, rule)
		}
	}
	wg.Wait()
}
