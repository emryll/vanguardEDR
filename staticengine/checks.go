package main

import (
	"os"
)

// true indicates a match
func CheckHash(file *os.File) (bool, error) {
	//TODO: malwarebazaar hash lookup with api
}

func CheckEntropy() int {
	//TODO: different entropy thresholds for different common file types
	//TODO: also look at chunks and their entropy

}

func CheckStreams() int {
	//TODO: are there other streams?
	//TODO: is the other stream a PE file? (highest score)
	//TODO: is the other stream very high entropy? (mid score)
	//TODO: other streams (not MOTW), but not as described above (low score)
	//TODO: no streams = score 0
}
