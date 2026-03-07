package router

var validChecks = map[string]bool{
	"secret-scan":      true,
	"safety-guard":     true,
	"guard-branch":     true,
	"lint":             true,
	"test-nudge":       true,
	"test-nudge-reset": true,
}

func ResolveChecks(event string, tool string, requested []string) []string {
	var result []string
	for _, name := range requested {
		if validChecks[name] {
			result = append(result, name)
		}
	}
	return result
}
