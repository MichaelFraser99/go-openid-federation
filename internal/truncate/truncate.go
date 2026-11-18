package truncate

import "unicode/utf8"

func TruncateAtCharacter(value string, limit int) string {
	limit = max(limit, 0)
	if len(value) <= limit {
		return value
	}
	cut := limit
	for step := 0; step < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(value[cut]); step++ {
		cut--
	}
	if !utf8.RuneStart(value[cut]) {
		cut = limit
	}
	return value[:cut] + "..."
}

const MaxErrorDescriptionBytes = 256

func TruncateForResponse(value string) string {
	return TruncateAtCharacter(value, MaxErrorDescriptionBytes)
}
