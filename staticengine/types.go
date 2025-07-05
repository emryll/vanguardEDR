package main

type HashLookup struct {
	Sha256 string
	Status string `json:"query_status"` // ok / hash_not_found
	Data   []struct {
		Signature string   `json:"signature"`
		Tags      []string `json:"tags"`
		YaraRules []struct {
			Name        string `json:"rule_name"`
			Description string `json:"description"`
		} `json:"yara_rules"`
	} `json:"data"`
}

type ApiPattern struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ApiCalls    [][]string `json:"api_calls"` // lets you define all possible options, so can do both kernel32 and nt
	Severity    int        `json:"severity"`  // 0, 1, 2
	Score       int        `json:"score"`
}

type MalApi struct {
	Name     string   `json:"name"`
	Severity int      `json:"severity"`
	Score    int      `json:"score"`
	Tag      []string `json:"tag"`
}

type StaticResult struct {
	Name        string
	Description string
	Tag         string
	Category    []string
	Score       int
	Severity    int // 0, 1, 2 (low, medium, high)
}
