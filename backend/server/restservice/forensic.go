package restservice

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"isc.org/stork/server/agentcomm"
	dbmodel "isc.org/stork/server/database/model"
	"isc.org/stork/server/gen/models"
	dhcp "isc.org/stork/server/gen/restapi/operations/d_h_c_p"
)

type forensicRow struct {
	timestamp time.Time
	address   string
	message   string
	daemonID  int64
	label     string
}

// GetForensicLeases returns a read-only view of Kea legal-log rows. The agent
// opens the forensic database as a read-only session, so this call does not
// write to it.
func (r *RestAPI) GetForensicLeases(ctx context.Context, params dhcp.GetForensicLeasesParams) middleware.Responder {
	_, user := r.SessionManager.Logged(ctx)
	if user == nil {
		msg := "Unable to identify the user requesting forensic leases"
		return dhcp.NewGetForensicLeasesDefault(http.StatusBadRequest).WithPayload(&models.APIError{Message: &msg})
	}
	if !user.InGroup(&dbmodel.SystemGroup{ID: dbmodel.SuperAdminGroupID}) &&
		!user.InGroup(&dbmodel.SystemGroup{ID: dbmodel.AdminGroupID}) {
		msg := "User is forbidden to access forensic lease information"
		return dhcp.NewGetForensicLeasesDefault(http.StatusForbidden).WithPayload(&models.APIError{Message: &msg})
	}

	var start int64
	if params.Start != nil {
		start = *params.Start
	}
	var limit int64 = 10
	if params.Limit != nil {
		limit = *params.Limit
	}
	fromText := strings.TrimSpace(params.From)
	toText := strings.TrimSpace(params.To)
	if fromText == "" || toText == "" {
		msg := "Forensic search requires a start and end time"
		return dhcp.NewGetForensicLeasesDefault(http.StatusBadRequest).WithPayload(&models.APIError{Message: &msg})
	}
	filter := agentcomm.ForensicFilter{Offset: 0, Limit: 0}
	if params.Text != nil {
		filter.Text = *params.Text
	}
	if params.Address != nil {
		filter.Address = *params.Address
	}
	parsedFrom, err := time.Parse(time.RFC3339, fromText)
	if err != nil {
		msg := "from must be an RFC3339 timestamp"
		return dhcp.NewGetForensicLeasesDefault(http.StatusBadRequest).WithPayload(&models.APIError{Message: &msg})
	}
	parsedTo, err := time.Parse(time.RFC3339, toText)
	if err != nil {
		msg := "to must be an RFC3339 timestamp"
		return dhcp.NewGetForensicLeasesDefault(http.StatusBadRequest).WithPayload(&models.APIError{Message: &msg})
	}
	if parsedFrom.After(parsedTo) {
		msg := "Forensic search start is after the end"
		return dhcp.NewGetForensicLeasesDefault(http.StatusBadRequest).WithPayload(&models.APIError{Message: &msg})
	}
	filter.From = parsedFrom
	filter.To = parsedTo

	rows, total, err := r.collectForensicRows(ctx, params.DaemonID, params.MachineID, filter, start, limit)
	if err != nil {
		msg := errors.WithMessage(err, "failed to query forensic leases").Error()
		log.Error(msg)
		return dhcp.NewGetForensicLeasesDefault(http.StatusInternalServerError).WithPayload(&models.APIError{Message: &msg})
	}

	items := make([]*models.ForensicLog, 0, len(rows))
	for _, row := range rows {
		timestamp := row.timestamp.UTC().Format(time.RFC3339Nano)
		address := row.address
		message := row.message
		daemonID := row.daemonID
		label := row.label
		items = append(items, &models.ForensicLog{
			Timestamp:   timestamp,
			Address:     address,
			Log:         message,
			DaemonID:    daemonID,
			DaemonLabel: label,
		})
	}
	return dhcp.NewGetForensicLeasesOK().WithPayload(&models.ForensicLogs{
		Total: &total,
		Items: items,
	})
}

func (r *RestAPI) collectForensicRows(ctx context.Context, daemonID, machineID *int64, filter agentcomm.ForensicFilter, start, limit int64) ([]forensicRow, int64, error) {
	daemons, err := dbmodel.GetDHCPDaemons(r.DB)
	if err != nil {
		return nil, 0, err
	}
	type dbKey struct {
		machine int64
		host    string
		name    string
		port    int
	}
	seen := map[dbKey]struct{}{}
	var picked []dbmodel.Daemon
	for _, daemon := range daemons {
		if daemonID != nil && daemon.ID != *daemonID {
			continue
		}
		if machineID != nil && daemon.MachineID != *machineID {
			continue
		}
		if daemon.KeaDaemon == nil || daemon.KeaDaemon.Config == nil || daemon.KeaDaemon.Config.Config == nil || !daemon.Active {
			continue
		}
		databases := daemon.KeaDaemon.Config.GetAllDatabases()
		if databases.Forensic == nil || databases.Forensic.Type != "postgresql" {
			continue
		}
		key := dbKey{daemon.MachineID, databases.Forensic.Host, databases.Forensic.Name, databases.Forensic.Port}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		picked = append(picked, daemon)
	}

	perSourceLimit := int64(0)
	if limit > 0 {
		perSourceLimit = start + limit
	}
	query := filter
	query.Offset = 0
	query.Limit = perSourceLimit

	var (
		rows  []forensicRow
		total int64
		errs  []error
	)
	for _, daemon := range picked {
		rsp, err := r.Agents.QueryForensicLogs(ctx, &daemon, query)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if rsp == nil {
			continue
		}
		total += rsp.Total
		label := daemon.GetLabel()
		for _, entry := range rsp.Logs {
			rows = append(rows, forensicRow{
				timestamp: time.UnixMilli(entry.TimestampUnixMilli),
				address:   entry.Address,
				message:   entry.Log,
				daemonID:  daemon.ID,
				label:     label,
			})
		}
	}
	if len(rows) == 0 && len(errs) > 0 {
		return nil, 0, errors.Wrap(errs[0], "forensic query failed")
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].timestamp.After(rows[j].timestamp)
	})
	if limit == 0 {
		if start > 0 && start < int64(len(rows)) {
			rows = rows[start:]
		} else if start > 0 {
			rows = nil
		}
		return rows, total, nil
	}
	if start >= int64(len(rows)) {
		return nil, total, nil
	}
	end := start + limit
	if end > int64(len(rows)) {
		end = int64(len(rows))
	}
	return rows[start:end], total, nil
}
