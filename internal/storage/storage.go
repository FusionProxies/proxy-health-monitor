// Package storage keeps check results, proxy state, incidents and the alert
// history in a local SQLite database (pure Go driver, no cgo).
//
// Only what monitoring needs is stored: timings, status codes, failure
// classes and redacted error messages. No response bodies, no headers, no
// credentials and nothing about traffic other than the monitor's own checks.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/stats"
)

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checks (
	id           INTEGER PRIMARY KEY,
	proxy        TEXT    NOT NULL,
	ts           INTEGER NOT NULL,
	ok           INTEGER NOT NULL,
	error_class  TEXT    NOT NULL DEFAULT '',
	error        TEXT    NOT NULL DEFAULT '',
	status_code  INTEGER NOT NULL DEFAULT 0,
	dns_ms       REAL    NOT NULL DEFAULT 0,
	connect_ms   REAL    NOT NULL DEFAULT 0,
	handshake_ms REAL    NOT NULL DEFAULT 0,
	tls_ms       REAL    NOT NULL DEFAULT 0,
	ttfb_ms      REAL    NOT NULL DEFAULT 0,
	total_ms     REAL    NOT NULL DEFAULT 0,
	bytes_in     INTEGER NOT NULL DEFAULT 0,
	bytes_out    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS checks_proxy_ts ON checks(proxy, ts);
CREATE INDEX IF NOT EXISTS checks_ts ON checks(ts);
CREATE TABLE IF NOT EXISTS incidents (
	id         INTEGER PRIMARY KEY,
	proxy      TEXT    NOT NULL,
	kind       TEXT    NOT NULL,
	started_at INTEGER NOT NULL,
	ended_at   INTEGER,
	reason     TEXT    NOT NULL DEFAULT '',
	last_error TEXT    NOT NULL DEFAULT '',
	failures   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_proxy ON incidents(proxy, started_at);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents(ended_at);
CREATE TABLE IF NOT EXISTS proxy_state (
	proxy                 TEXT PRIMARY KEY,
	state                 TEXT    NOT NULL,
	consecutive_failures  INTEGER NOT NULL DEFAULT 0,
	consecutive_successes INTEGER NOT NULL DEFAULT 0,
	last_check_at         INTEGER NOT NULL DEFAULT 0,
	last_ok_at            INTEGER NOT NULL DEFAULT 0,
	last_failure_at       INTEGER NOT NULL DEFAULT 0,
	last_error            TEXT    NOT NULL DEFAULT '',
	last_error_class      TEXT    NOT NULL DEFAULT '',
	last_total_ms         REAL    NOT NULL DEFAULT 0,
	updated_at            INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY,
	ts          INTEGER NOT NULL,
	proxy       TEXT    NOT NULL,
	kind        TEXT    NOT NULL,
	incident_id INTEGER NOT NULL DEFAULT 0,
	status      TEXT    NOT NULL,
	channels    TEXT    NOT NULL DEFAULT '',
	message     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
`

// Store is the database handle. It is safe for concurrent use.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serializes writes; reads run in parallel (WAL)
}

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, err
			}
		}
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1) // every connection would get its own empty database
	} else {
		db.SetMaxOpenConns(8)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	var v string
	err = db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES ('schema_version', ?)`, fmt.Sprint(schemaVersion)); err != nil {
			_ = db.Close()
			return nil, err
		}
	case err != nil:
		_ = db.Close()
		return nil, err
	case v != fmt.Sprint(schemaVersion):
		_ = db.Close()
		return nil, fmt.Errorf("%s has schema version %s, this build expects %d", path, v, schemaVersion)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func dms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// InsertCheck stores one result.
func (s *Store) InsertCheck(r checks.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO checks (proxy, ts, ok, error_class, error, status_code, dns_ms, connect_ms, handshake_ms, tls_ms, ttfb_ms, total_ms, bytes_in, bytes_out)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Proxy, ms(r.Time), boolInt(r.OK), string(r.Class), r.Error, r.StatusCode,
		dms(r.DNS), dms(r.Connect), dms(r.Handshake), dms(r.TLS), dms(r.TTFB), dms(r.Total), r.BytesIn, r.BytesOut)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CheckRow is a stored check.
type CheckRow struct {
	Time        time.Time `json:"time"`
	OK          bool      `json:"ok"`
	Class       string    `json:"error_class,omitempty"`
	Error       string    `json:"error,omitempty"`
	StatusCode  int       `json:"status_code,omitempty"`
	DNSMS       float64   `json:"dns_ms"`
	ConnectMS   float64   `json:"connect_ms"`
	HandshakeMS float64   `json:"handshake_ms"`
	TLSMS       float64   `json:"tls_ms"`
	TTFBMS      float64   `json:"ttfb_ms"`
	TotalMS     float64   `json:"total_ms"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
}

// Checks returns checks of one proxy in [from, to), newest first. onlyFailed
// limits the result to failures. limit <= 0 means no limit.
func (s *Store) Checks(proxy string, from, to time.Time, onlyFailed bool, limit int) ([]CheckRow, error) {
	q := `SELECT ts, ok, error_class, error, status_code, dns_ms, connect_ms, handshake_ms, tls_ms, ttfb_ms, total_ms, bytes_in, bytes_out
		FROM checks WHERE proxy = ? AND ts >= ? AND ts < ?`
	if onlyFailed {
		q += ` AND ok = 0`
	}
	q += ` ORDER BY ts DESC`
	args := []any{proxy, ms(from), ms(to)}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckRow
	for rows.Next() {
		var c CheckRow
		var ts int64
		var ok int
		if err := rows.Scan(&ts, &ok, &c.Class, &c.Error, &c.StatusCode, &c.DNSMS, &c.ConnectMS, &c.HandshakeMS, &c.TLSMS, &c.TTFBMS, &c.TotalMS, &c.BytesIn, &c.BytesOut); err != nil {
			return nil, err
		}
		c.Time, c.OK = fromMS(ts), ok == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// Samples returns the statistics view of checks of one proxy in [from, to),
// oldest first.
func (s *Store) Samples(proxy string, from, to time.Time) ([]stats.Sample, error) {
	rows, err := s.db.Query(`SELECT ts, ok, total_ms, ttfb_ms, error_class FROM checks
		WHERE proxy = ? AND ts >= ? AND ts < ? ORDER BY ts`, proxy, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stats.Sample
	for rows.Next() {
		var x stats.Sample
		var ts int64
		var ok int
		if err := rows.Scan(&ts, &ok, &x.TotalMS, &x.TTFBMS, &x.Class); err != nil {
			return nil, err
		}
		x.Time, x.OK = fromMS(ts), ok == 1
		out = append(out, x)
	}
	return out, rows.Err()
}

// Counts returns how many checks and successes one proxy had in [from, to).
func (s *Store) Counts(proxy string, from, to time.Time) (checksN, okN int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(ok), 0) FROM checks WHERE proxy = ? AND ts >= ? AND ts < ?`,
		proxy, ms(from), ms(to)).Scan(&checksN, &okN)
	return
}

// ProxyState is the latest known health of one proxy.
type ProxyState struct {
	Proxy                string    `json:"proxy"`
	State                string    `json:"state"`
	ConsecutiveFailures  int       `json:"consecutive_failures"`
	ConsecutiveSuccesses int       `json:"consecutive_successes"`
	LastCheck            time.Time `json:"last_check"`
	LastOK               time.Time `json:"last_ok"`
	LastFailure          time.Time `json:"last_failure"`
	LastError            string    `json:"last_error,omitempty"`
	LastErrorClass       string    `json:"last_error_class,omitempty"`
	LastTotalMS          float64   `json:"last_total_ms"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// SaveState writes the state of one proxy.
func (s *Store) SaveState(st ProxyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO proxy_state (proxy, state, consecutive_failures, consecutive_successes, last_check_at, last_ok_at, last_failure_at, last_error, last_error_class, last_total_ms, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(proxy) DO UPDATE SET state=excluded.state, consecutive_failures=excluded.consecutive_failures,
			consecutive_successes=excluded.consecutive_successes, last_check_at=excluded.last_check_at, last_ok_at=excluded.last_ok_at,
			last_failure_at=excluded.last_failure_at, last_error=excluded.last_error, last_error_class=excluded.last_error_class,
			last_total_ms=excluded.last_total_ms, updated_at=excluded.updated_at`,
		st.Proxy, st.State, st.ConsecutiveFailures, st.ConsecutiveSuccesses, ms(st.LastCheck), ms(st.LastOK), ms(st.LastFailure),
		st.LastError, st.LastErrorClass, st.LastTotalMS, ms(st.UpdatedAt))
	return err
}

// States returns the stored state of every proxy.
func (s *Store) States() (map[string]ProxyState, error) {
	rows, err := s.db.Query(`SELECT proxy, state, consecutive_failures, consecutive_successes, last_check_at, last_ok_at, last_failure_at, last_error, last_error_class, last_total_ms, updated_at FROM proxy_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProxyState{}
	for rows.Next() {
		var st ProxyState
		var lc, lo, lf, up int64
		if err := rows.Scan(&st.Proxy, &st.State, &st.ConsecutiveFailures, &st.ConsecutiveSuccesses, &lc, &lo, &lf, &st.LastError, &st.LastErrorClass, &st.LastTotalMS, &up); err != nil {
			return nil, err
		}
		st.LastCheck, st.LastOK, st.LastFailure, st.UpdatedAt = fromMS(lc), fromMS(lo), fromMS(lf), fromMS(up)
		out[st.Proxy] = st
	}
	return out, rows.Err()
}

// ForgetProxiesExcept removes the state (not the history) of proxies that are
// no longer configured and closes their open incidents.
func (s *Store) ForgetProxiesExcept(names []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := "''"
	args := make([]any, 0, len(names)+1)
	if len(names) > 0 {
		keep = strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
		for _, n := range names {
			args = append(args, n)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM proxy_state WHERE proxy NOT IN (`+keep+`)`, args...); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE incidents SET ended_at = ?, reason = reason || ' (closed: proxy removed from the configuration)'
		WHERE ended_at IS NULL AND proxy NOT IN (`+keep+`)`, append([]any{ms(at)}, args...)...)
	return err
}

// Incident is a period during which a proxy was down, slow or below its
// availability threshold.
type Incident struct {
	ID        int64      `json:"id"`
	Proxy     string     `json:"proxy"`
	Kind      string     `json:"kind"` // down, latency, availability
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at"`
	Open      bool       `json:"open"`
	DurationS float64    `json:"duration_seconds"`
	Reason    string     `json:"reason"`
	LastError string     `json:"last_error,omitempty"`
	Failures  int        `json:"failures"`
}

// OpenIncident starts an incident and returns its id.
func (s *Store) OpenIncident(proxy, kind, reason, lastErr string, failures int, at time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`INSERT INTO incidents (proxy, kind, started_at, reason, last_error, failures) VALUES (?,?,?,?,?,?)`,
		proxy, kind, ms(at), reason, lastErr, failures)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateIncident records the latest error and failure count of an open incident.
func (s *Store) UpdateIncident(id int64, lastErr string, failures int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE incidents SET last_error = ?, failures = ? WHERE id = ? AND ended_at IS NULL`, lastErr, failures, id)
	return err
}

// CloseIncident ends an incident.
func (s *Store) CloseIncident(id int64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE incidents SET ended_at = ? WHERE id = ? AND ended_at IS NULL`, ms(at), id)
	return err
}

// IncidentFilter selects incidents. Zero values mean "any".
type IncidentFilter struct {
	Proxy    string
	OnlyOpen bool
	Since    time.Time // incidents that were open at any time after Since
	Limit    int
}

// Incidents lists incidents, newest first.
func (s *Store) Incidents(f IncidentFilter) ([]Incident, error) {
	q := `SELECT id, proxy, kind, started_at, ended_at, reason, last_error, failures FROM incidents WHERE 1=1`
	var args []any
	if f.Proxy != "" {
		q += ` AND proxy = ?`
		args = append(args, f.Proxy)
	}
	if f.OnlyOpen {
		q += ` AND ended_at IS NULL`
	}
	if !f.Since.IsZero() {
		q += ` AND (ended_at IS NULL OR ended_at >= ?)`
		args = append(args, ms(f.Since))
	}
	q += ` ORDER BY started_at DESC, id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var out []Incident
	for rows.Next() {
		var in Incident
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&in.ID, &in.Proxy, &in.Kind, &started, &ended, &in.Reason, &in.LastError, &in.Failures); err != nil {
			return nil, err
		}
		in.StartedAt = fromMS(started)
		end := now
		if ended.Valid {
			t := fromMS(ended.Int64)
			in.EndedAt = &t
			end = t
		} else {
			in.Open = true
		}
		in.DurationS = end.Sub(in.StartedAt).Seconds()
		out = append(out, in)
	}
	return out, rows.Err()
}

// AlertRecord is one alert decision, sent or suppressed.
type AlertRecord struct {
	Time       time.Time `json:"time"`
	Proxy      string    `json:"proxy"`
	Kind       string    `json:"kind"`
	IncidentID int64     `json:"incident_id,omitempty"`
	Status     string    `json:"status"` // sent, suppressed, failed
	Channels   string    `json:"channels,omitempty"`
	Message    string    `json:"message"`
}

// RecordAlert stores an alert decision.
func (s *Store) RecordAlert(a AlertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO alerts (ts, proxy, kind, incident_id, status, channels, message) VALUES (?,?,?,?,?,?,?)`,
		ms(a.Time), a.Proxy, a.Kind, a.IncidentID, a.Status, a.Channels, a.Message)
	return err
}

// Alerts returns recent alert decisions, newest first.
func (s *Store) Alerts(limit int) ([]AlertRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT ts, proxy, kind, incident_id, status, channels, message FROM alerts ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRecord
	for rows.Next() {
		var a AlertRecord
		var ts int64
		if err := rows.Scan(&ts, &a.Proxy, &a.Kind, &a.IncidentID, &a.Status, &a.Channels, &a.Message); err != nil {
			return nil, err
		}
		a.Time = fromMS(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

// LastSentAlerts returns, per proxy and kind, when an alert was last sent
// after since. The alert manager uses it to keep cooldowns across restarts.
func (s *Store) LastSentAlerts(since time.Time) (map[[2]string]time.Time, error) {
	rows, err := s.db.Query(`SELECT proxy, kind, MAX(ts) FROM alerts WHERE status = 'sent' AND ts >= ? GROUP BY proxy, kind`, ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[[2]string]time.Time{}
	for rows.Next() {
		var p, k string
		var ts int64
		if err := rows.Scan(&p, &k, &ts); err != nil {
			return nil, err
		}
		out[[2]string{p, k}] = fromMS(ts)
	}
	return out, rows.Err()
}

// Prune deletes checks older than checksBefore and closed incidents and alert
// records older than incidentsBefore. It deletes in batches so the monitor
// keeps writing while it runs.
func (s *Store) Prune(checksBefore, incidentsBefore time.Time) (checksDeleted, incidentsDeleted int64, err error) {
	for {
		s.mu.Lock()
		res, err := s.db.Exec(`DELETE FROM checks WHERE id IN (SELECT id FROM checks WHERE ts < ? LIMIT 5000)`, ms(checksBefore))
		s.mu.Unlock()
		if err != nil {
			return checksDeleted, incidentsDeleted, err
		}
		n, _ := res.RowsAffected()
		checksDeleted += n
		if n < 5000 {
			break
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM incidents WHERE ended_at IS NOT NULL AND ended_at < ?`, ms(incidentsBefore))
	if err != nil {
		return checksDeleted, 0, err
	}
	incidentsDeleted, _ = res.RowsAffected()
	if _, err := s.db.Exec(`DELETE FROM alerts WHERE ts < ?`, ms(incidentsBefore)); err != nil {
		return checksDeleted, incidentsDeleted, err
	}
	return checksDeleted, incidentsDeleted, nil
}

// TotalChecks counts every stored check (for status output and tests).
func (s *Store) TotalChecks() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM checks`).Scan(&n)
	return n, err
}
