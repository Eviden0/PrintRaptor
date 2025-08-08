package main

import (
	"PrintRaptor/config"
	"PrintRaptor/models"
	"PrintRaptor/scan"
	"fmt"
	"log"
	"time"
)

func main() {
	logo := `  ____  ____  ___ _   _ _____ ____     _    ____ _____ ___  ____   
 |  _ \|  _ \|_ _| \ | |_   _|  _ \   / \  |  _ |_   _/ _ \|  _ \  
 | |_) | |_) || ||  \| | | | | |_) | / _ \ | |_) || || | | | |_) | 
 |  __/|  _ < | || |\  | | | |  _ < / ___ \|  __/ | || |_| |  _ <  
 |_|   |_| \_|___|_| \_| |_| |_| \_/_/   \_|_|    |_| \___/|_| \_\ 

                                          𝓑𝓨 : 𝓔𝓿𝓲𝓭𝓮𝓷`
	fmt.Println(logo)
	start := time.Now()
	config.Load()
	scan.Scan()
	log.Println("扫描完毕")
	models.Close()
	elapsed := time.Since(start)
	fmt.Printf("[✔] 扫描完成，耗时: %s\n", elapsed)
}
