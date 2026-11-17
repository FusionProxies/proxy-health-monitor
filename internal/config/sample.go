package config

import _ "embed"

// Sample is the annotated configuration written by `proxy-monitor init`.
//
//go:embed sample.yaml
var Sample string
