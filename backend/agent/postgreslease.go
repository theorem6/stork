package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	keaconfig "isc.org/stork/daemoncfg/kea"
	keadata "isc.org/stork/daemondata/kea"
	"isc.org/stork/datamodel/daemonname"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// ForensicLog is one row from Kea's legal-log (forensic) table.
type ForensicLog struct {
	Timestamp time.Time
	Address   string
	Log       string
}

// ForensicFilter selects forensic rows. From and To are required so a query
// cannot scan the full legal-log history. Limit zero returns every row in
// that time range.
type ForensicFilter struct {
	Address string
	Text    string
	From    time.Time
	To      time.Time
	Offset  int64
	Limit   int64
}

// openReadOnlyPostgres connects with the same user and password Kea uses to
// write, and forces the session to be read-only so this process cannot modify
// the database.
func openReadOnlyPostgres(db *keaconfig.Database) (*sql.DB, error) {
	if db == nil {
		return nil, errors.New("no PostgreSQL database configuration")
	}
	if db.Type != "" && db.Type != "postgresql" {
		return nil, errors.Errorf("database type %q is not PostgreSQL", db.Type)
	}
	host := db.Host
	if host == "" {
		host = "localhost"
	}
	port := db.Port
	if port == 0 {
		port = 5432
	}
	name := db.Name
	if name == "" {
		return nil, errors.New("PostgreSQL database name is empty")
	}
	user := db.User
	if user == "" {
		user = "postgres"
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, db.Password),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/" + name,
	}
	query := u.Query()
	if db.TrustAnchor != "" {
		query.Set("sslmode", "verify-full")
		query.Set("sslrootcert", db.TrustAnchor)
		if db.CertFile != "" {
			query.Set("sslcert", db.CertFile)
		}
		if db.KeyFile != "" {
			query.Set("sslkey", db.KeyFile)
		}
	} else {
		query.Set("sslmode", "disable")
	}
	// Session is read-only before any statement runs.
	query.Set("options", "-c default_transaction_read_only=on -c statement_timeout=600000")
	u.RawQuery = query.Encode()

	conn, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to open PostgreSQL")
	}
	conn.SetMaxOpenConns(2)
	conn.SetConnMaxLifetime(time.Minute)
	return conn, nil
}

func withReadOnlyTx(ctx context.Context, conn *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.Wrap(err, "failed to begin read-only transaction")
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return nil
}

// queryPostgresLeases reads lease4 or lease6 and returns the same fields the
// memfile snooper produces.
func queryPostgresLeases(ctx context.Context, kind daemonname.Name, db *keaconfig.Database, minCLTT uint64) ([]*keadata.Lease, error) {
	conn, err := openReadOnlyPostgres(db)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var leases []*keadata.Lease
	err = withReadOnlyTx(ctx, conn, func(tx *sql.Tx) error {
		switch kind {
		case daemonname.DHCPv4:
			leases, err = queryLease4(ctx, tx, minCLTT)
		case daemonname.DHCPv6:
			leases, err = queryLease6(ctx, tx, minCLTT)
		default:
			err = errors.Errorf("cannot read leases for daemon %s", kind)
		}
		return err
	})
	return leases, err
}

func queryLease4(ctx context.Context, tx *sql.Tx, minCLTT uint64) ([]*keadata.Lease, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT address::text,
		       hwaddr,
		       client_id,
		       COALESCE(valid_lifetime, 0),
		       EXTRACT(EPOCH FROM expire)::bigint,
		       COALESCE(subnet_id, 0),
		       COALESCE(fqdn_fwd, false),
		       COALESCE(fqdn_rev, false),
		       COALESCE(hostname, ''),
		       COALESCE(state, 0),
		       COALESCE(user_context::text, '')
		FROM lease4
		WHERE (EXTRACT(EPOCH FROM expire)::bigint - COALESCE(valid_lifetime, 0)) >= $1
	`, minCLTT)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query lease4")
	}
	defer rows.Close()

	var leases []*keadata.Lease
	for rows.Next() {
		var address string
		var hwaddr, clientID []byte
		var lifetime, expire, subnet int64
		var fqdnFwd, fqdnRev bool
		var hostname, userCtxText string
		var state int64
		if err := rows.Scan(&address, &hwaddr, &clientID, &lifetime, &expire, &subnet, &fqdnFwd, &fqdnRev, &hostname, &state, &userCtxText); err != nil {
			return nil, errors.Wrap(err, "failed to scan lease4")
		}
		ip, err := kea4Address(address)
		if err != nil {
			return nil, err
		}
		userCtx, err := parseUserContext(userCtxText)
		if err != nil {
			return nil, err
		}
		cltt := uint64(expire - lifetime)
		lease := keadata.NewLease4(ip, colonHex(hwaddr), colonHex(clientID), cltt, uint32(lifetime), uint32(subnet), fqdnFwd, fqdnRev, hostname, uint32(state), userCtx)
		leases = append(leases, &lease)
	}
	return leases, errors.Wrap(rows.Err(), "failed while reading lease4")
}

func queryLease6(ctx context.Context, tx *sql.Tx, minCLTT uint64) ([]*keadata.Lease, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT address::text,
		       duid,
		       COALESCE(valid_lifetime, 0),
		       EXTRACT(EPOCH FROM expire)::bigint,
		       COALESCE(subnet_id, 0),
		       COALESCE(pref_lifetime, 0),
		       COALESCE(lease_type, 0),
		       COALESCE(iaid, 0),
		       COALESCE(prefix_len, 0),
		       COALESCE(fqdn_fwd, false),
		       COALESCE(fqdn_rev, false),
		       COALESCE(hostname, ''),
		       hwaddr,
		       COALESCE(state, 0),
		       COALESCE(user_context::text, ''),
		       hwtype,
		       hwaddr_source
		FROM lease6
		WHERE (EXTRACT(EPOCH FROM expire)::bigint - COALESCE(valid_lifetime, 0)) >= $1
	`, minCLTT)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query lease6")
	}
	defer rows.Close()

	var leases []*keadata.Lease
	for rows.Next() {
		var address, hostname, userCtxText string
		var duid, hwaddr []byte
		var lifetime, expire, subnet, pref, leaseType, iaid, prefix, state int64
		var fqdnFwd, fqdnRev bool
		var hwtype, hwaddrSource sql.NullInt64
		if err := rows.Scan(&address, &duid, &lifetime, &expire, &subnet, &pref, &leaseType, &iaid, &prefix, &fqdnFwd, &fqdnRev, &hostname, &hwaddr, &state, &userCtxText, &hwtype, &hwaddrSource); err != nil {
			return nil, errors.Wrap(err, "failed to scan lease6")
		}
		userCtx, err := parseUserContext(userCtxText)
		if err != nil {
			return nil, err
		}
		var hwtypePtr *uint32
		if hwtype.Valid {
			v := uint32(hwtype.Int64)
			hwtypePtr = &v
		}
		source := ""
		if hwaddrSource.Valid {
			source = strconv.FormatInt(hwaddrSource.Int64, 10)
		}
		cltt := uint64(expire - lifetime)
		lease := keadata.NewLease6(
			address,
			colonHex(duid),
			lease6TypeName(leaseType),
			cltt,
			uint32(lifetime),
			uint32(subnet),
			uint32(pref),
			uint32(iaid),
			uint8(prefix),
			fqdnFwd,
			fqdnRev,
			hostname,
			colonHex(hwaddr),
			uint32(state),
			userCtx,
			hwtypePtr,
			source,
		)
		leases = append(leases, &lease)
	}
	return leases, errors.Wrap(rows.Err(), "failed while reading lease6")
}

// queryForensicLogs reads legal-log rows. The transaction is read-only.
// Both ends of the time range are required.
func queryForensicLogs(ctx context.Context, db *keaconfig.Database, filter ForensicFilter) ([]ForensicLog, int64, error) {
	if filter.From.IsZero() || filter.To.IsZero() {
		return nil, 0, errors.New("forensic search requires a start and end time")
	}
	if filter.From.After(filter.To) {
		return nil, 0, errors.New("forensic search start is after the end")
	}
	if db == nil || db.Type != "postgresql" {
		return nil, 0, errors.New("forensic logging is not stored in PostgreSQL")
	}
	conn, err := openReadOnlyPostgres(db)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	address := escapeLike(filter.Address)
	text := escapeLike(filter.Text)
	var from, to any
	if !filter.From.IsZero() {
		from = filter.From.UTC()
	}
	if !filter.To.IsZero() {
		to = filter.To.UTC()
	}

	var (
		logs  []ForensicLog
		total int64
	)
	err = withReadOnlyTx(ctx, conn, func(tx *sql.Tx) error {
		where := "($1 = '' OR address ILIKE $1 ESCAPE '\\') AND ($2 = '' OR log ILIKE $2 ESCAPE '\\') AND ($3::timestamptz IS NULL OR timestamp >= $3) AND ($4::timestamptz IS NULL OR timestamp <= $4)"
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs WHERE `+where, address, text, from, to).Scan(&total); err != nil {
			return errors.Wrap(err, "failed to count forensic logs")
		}
		limitClause := ""
		args := []any{address, text, from, to}
		if filter.Limit > 0 {
			limitClause = " LIMIT $5 OFFSET $6"
			args = append(args, filter.Limit, filter.Offset)
		} else if filter.Offset > 0 {
			limitClause = " OFFSET $5"
			args = append(args, filter.Offset)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT timestamp, COALESCE(address, ''), COALESCE(log, '')
			FROM logs
			WHERE `+where+`
			ORDER BY timestamp DESC`+limitClause, args...)
		if err != nil {
			return errors.Wrap(err, "failed to query forensic logs")
		}
		defer rows.Close()
		for rows.Next() {
			var entry ForensicLog
			if err := rows.Scan(&entry.Timestamp, &entry.Address, &entry.Log); err != nil {
				return errors.Wrap(err, "failed to scan forensic log")
			}
			logs = append(logs, entry)
		}
		return errors.Wrap(rows.Err(), "failed while reading forensic logs")
	})
	return logs, total, err
}

func kea4Address(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, ".") || strings.Contains(raw, ":") {
		return raw, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return "", errors.Wrapf(err, "cannot parse lease4 address %q", raw)
	}
	return ipv4FromUint32(uint32(n)), nil
}

func ipv4FromUint32(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

func lease6TypeName(v int64) string {
	switch v {
	case 0:
		return "IA_NA"
	case 1:
		return "IA_TA"
	case 2:
		return "IA_PD"
	default:
		return strconv.FormatInt(v, 10)
	}
}

func parseUserContext(text string) (map[string]any, error) {
	if text == "" || text == "null" {
		return nil, nil
	}
	var userCtx map[string]any
	if err := json.Unmarshal([]byte(text), &userCtx); err != nil {
		return nil, errors.Wrap(err, "the user context is not valid JSON")
	}
	return userCtx, nil
}

func escapeLike(s string) string {
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + replacer.Replace(s) + "%"
}
