package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const serverCols = `id, name, url, owner_group, allow_private, paused, created_at`

// rowScanner is the Scan half of *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanServer(sc rowScanner) (Server, error) {
	var (
		srv     Server
		private int
		paused  int
		created string
	)
	if err := sc.Scan(&srv.ID, &srv.Name, &srv.URL, &srv.OwnerGroup, &private, &paused, &created); err != nil {
		return Server{}, err
	}
	at, err := parseTime(created)
	if err != nil {
		return Server{}, err
	}
	srv.AllowPrivate = private == 1
	srv.Paused = paused == 1
	srv.CreatedAt = at
	return srv, nil
}

// loadServerRow finds a server by exact name. Any name that is not registered,
// well-formed or not, is simply not found.
func loadServerRow(ctx context.Context, q queryer, name string) (Server, error) {
	srv, err := scanServer(q.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE name = ?`, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Server{}, fmt.Errorf("%w: server %s", ErrNotFound, quote(name))
	case err != nil:
		return Server{}, fmt.Errorf("catalog: load server: %w", err)
	}
	return srv, nil
}

// AddServer registers an upstream. ErrExists if the name is taken, ErrInvalid
// for a bad name or URL.
func (s *Store) AddServer(ctx context.Context, spec ServerSpec, by Actor) (Server, error) {
	if err := validateServerSpec(spec); err != nil {
		return Server{}, err
	}
	actor, err := normalizeActor(by)
	if err != nil {
		return Server{}, err
	}
	var srv Server
	err = s.inTx(ctx, func(t *txn) error {
		_, err := loadServerRow(ctx, t, spec.Name)
		if err == nil {
			return fmt.Errorf("%w: server %s", ErrExists, quote(spec.Name))
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		id, err := t.insert(ctx,
			`INSERT INTO servers (name, url, owner_group, allow_private, paused, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
			spec.Name, spec.URL, spec.OwnerGroup, boolInt(spec.AllowPrivate), t.ts)
		if err != nil {
			return fmt.Errorf("catalog: add server: %w", err)
		}
		srv = Server{ID: id, ServerSpec: spec, CreatedAt: t.stamp}
		// The URL can carry a credential in its query string, so the audit
		// entry records the policy flag and a hash of the address, which
		// Integrity compares with the row (serverAddedDetail).
		return t.appendAudit(ctx, actor, evServerAdded, spec.Name, "", "", serverAddedDetail(spec))
	})
	if err != nil {
		return Server{}, err
	}
	return srv, nil
}

// PauseServer stops crawling a server (D9): RecordCrawl returns ErrPaused and
// Snapshot returns no tools, so nothing of it is served, while decisions keep
// working and the views still show it. It is the operator's remedy against an
// upstream that misbehaves. A paused server is ErrInvalid.
func (s *Store) PauseServer(ctx context.Context, name string, by Actor) error {
	return s.setPaused(ctx, name, by, true)
}

// ResumeServer lets crawls and serving continue. A server that is not paused
// is ErrInvalid.
func (s *Store) ResumeServer(ctx context.Context, name string, by Actor) error {
	return s.setPaused(ctx, name, by, false)
}

func (s *Store) setPaused(ctx context.Context, name string, by Actor, paused bool) error {
	actor, err := requireHuman(by)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(t *txn) error {
		srv, err := loadServerRow(ctx, t, name)
		if err != nil {
			return err
		}
		if srv.Paused == paused {
			return invalidf("server %s is already paused=%t", quote(name), paused)
		}
		if _, err := t.exec(ctx, `UPDATE servers SET paused = ? WHERE id = ?`, boolInt(paused), srv.ID); err != nil {
			return fmt.Errorf("catalog: update server: %w", err)
		}
		event := evServerResumed
		if paused {
			event = evServerPaused
		}
		return t.appendAudit(ctx, actor, event, srv.Name, "", "", pausedDetail(paused))
	})
}

// Servers lists registered upstreams ordered by name.
func (s *Store) Servers(ctx context.Context) ([]Server, error) {
	out := []Server{}
	err := s.inRead(ctx, func(q queryer) error {
		rows, err := q.QueryContext(ctx, `SELECT `+serverCols+` FROM servers ORDER BY name`)
		if err != nil {
			return fmt.Errorf("catalog: list servers: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			srv, err := scanServer(rows)
			if err != nil {
				return fmt.Errorf("catalog: list servers: %w", err)
			}
			out = append(out, srv)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server returns one upstream by name, or ErrNotFound.
func (s *Store) Server(ctx context.Context, name string) (Server, error) {
	var srv Server
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		srv, err = loadServerRow(ctx, q, name)
		return err
	})
	if err != nil {
		return Server{}, err
	}
	return srv, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
