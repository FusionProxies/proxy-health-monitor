// Package web holds the dashboard: plain HTML, CSS and JavaScript with no
// build step and no external requests, embedded into the binary.
package web

import "embed"

// Static is the dashboard file tree (static/index.html, static/app.js, ...).
//
//go:embed static
var Static embed.FS
