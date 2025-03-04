/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package pgbk

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/backend"
	pgcommon "github.com/gravitational/teleport/lib/backend/pgbk/common"
)

func init() {
	backend.MustRegister(Name, func(ctx context.Context, p backend.Params) (backend.Backend, error) {
		return NewFromParams(ctx, p)
	})
	backend.MustRegister(AltName, func(ctx context.Context, p backend.Params) (backend.Backend, error) {
		return NewFromParams(ctx, p)
	})
}

const (
	Name    = "postgresql"
	AltName = "postgres"

	// componentName is the component name used for logging.
	componentName = "pgbk"
)

const (
	defaultChangeFeedBatchSize = 1000
	defaultChangeFeedInterval  = backend.DefaultPollStreamPeriod

	defaultExpiryBatchSize = 1000
	defaultExpiryInterval  = 30 * time.Second
)

// Config is the configuration struct for [Backend]; outside of tests or custom
// code, it's usually generated by converting the [backend.Params] from the
// Teleport configuration file.
type Config struct {
	pgcommon.AuthConfig

	ConnString string `json:"conn_string"`

	ChangeFeedConnString   string         `json:"change_feed_conn_string"`
	ChangeFeedPollInterval types.Duration `json:"change_feed_poll_interval"`
	ChangeFeedBatchSize    int            `json:"change_feed_batch_size"`

	DisableExpiry   bool           `json:"disable_expiry"`
	ExpiryInterval  types.Duration `json:"expiry_interval"`
	ExpiryBatchSize int            `json:"expiry_batch_size"`
}

func (c *Config) CheckAndSetDefaults() error {
	if err := c.AuthConfig.Check(); err != nil {
		return trace.Wrap(err)
	}

	if c.ChangeFeedConnString == "" {
		c.ChangeFeedConnString = c.ConnString
	}
	if c.ChangeFeedPollInterval < 0 {
		return trace.BadParameter("change feed poll interval must be non-negative")
	}
	if c.ChangeFeedPollInterval == 0 {
		c.ChangeFeedPollInterval = types.Duration(defaultChangeFeedInterval)
	}
	if c.ChangeFeedBatchSize < 0 {
		return trace.BadParameter("change feed batch size must be non-negative")
	}
	if c.ChangeFeedBatchSize == 0 {
		c.ChangeFeedBatchSize = defaultChangeFeedBatchSize
	}

	if c.ExpiryInterval < 0 {
		return trace.BadParameter("expiry interval must be non-negative")
	}
	if c.ExpiryInterval == 0 {
		c.ExpiryInterval = types.Duration(defaultExpiryInterval)
	}
	if c.ExpiryBatchSize < 0 {
		return trace.BadParameter("expiry batch size must be non-negative")
	}
	if c.ExpiryBatchSize == 0 {
		c.ExpiryBatchSize = defaultExpiryBatchSize
	}

	return nil
}

// NewFromParams starts and returns a [*Backend] with the given params
// (generally read from the Teleport configuration file).
func NewFromParams(ctx context.Context, params backend.Params) (*Backend, error) {
	var cfg Config
	if err := utils.ObjectToStruct(params, &cfg); err != nil {
		return nil, trace.Wrap(err)
	}

	bk, err := NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return bk, nil
}

// NewWithConfig starts and returns a [*Backend] with the given [Config].
func NewWithConfig(ctx context.Context, cfg Config) (*Backend, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	feedConfig, err := pgxpool.ParseConfig(cfg.ChangeFeedConnString)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log := slog.With(teleport.ComponentKey, componentName)

	if err := cfg.AuthConfig.ApplyToPoolConfigs(ctx, log, poolConfig, feedConfig); err != nil {
		return nil, trace.Wrap(err)
	}

	const defaultTxIsoParamName = "default_transaction_isolation"
	if defaultTxIso := poolConfig.ConnConfig.RuntimeParams[defaultTxIsoParamName]; defaultTxIso != "" {
		const message = "The " + defaultTxIsoParamName + " parameter was overridden in the connection string; proceeding with an unsupported configuration."
		log.ErrorContext(ctx, message,
			defaultTxIsoParamName, defaultTxIso)
	} else {
		poolConfig.ConnConfig.RuntimeParams[defaultTxIsoParamName] = "serializable"
	}

	log.InfoContext(ctx, "Setting up backend.")

	pgcommon.TryEnsureDatabase(ctx, poolConfig, log)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := pgcommon.SetupAndMigrate(ctx, log, pool, "backend_version", schemas); err != nil {
		pool.Close()
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	b := &Backend{
		cfg:        cfg,
		feedConfig: feedConfig,

		log:    log,
		pool:   pool,
		buf:    backend.NewCircularBuffer(),
		cancel: cancel,
	}

	if !cfg.DisableExpiry {
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.backgroundExpiry(ctx)
		}()
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.backgroundChangeFeed(ctx)
	}()

	return b, nil
}

// Backend is a PostgreSQL-backed [backend.Backend].
type Backend struct {
	cfg        Config
	feedConfig *pgxpool.Config

	log  *slog.Logger
	pool *pgxpool.Pool
	buf  *backend.CircularBuffer

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (b *Backend) Close() error {
	b.cancel()
	b.wg.Wait()
	b.buf.Close()
	b.pool.Close()
	return nil
}

var schemas = []string{
	`CREATE TABLE kv (
		key bytea NOT NULL,
		value bytea NOT NULL,
		expires timestamptz,
		revision uuid NOT NULL,
		CONSTRAINT kv_pkey PRIMARY KEY (key)
	);
	CREATE INDEX kv_expires_idx ON kv (expires) WHERE expires IS NOT NULL;`,

	// v14.0.0 also had `CREATE PUBLICATION kv_pub FOR TABLE kv` in schema
	// version 2
	"ALTER TABLE kv REPLICA IDENTITY FULL;",
}

var _ backend.Backend = (*Backend)(nil)

// GetName implements [backend.Backend].
func (*Backend) GetName() string {
	return Name
}

// Create implements [backend.Backend].
func (b *Backend) Create(ctx context.Context, i backend.Item) (*backend.Lease, error) {
	revision := newRevision()
	i.Expires = i.Expires.UTC()
	created, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"INSERT INTO kv (key, value, expires, revision) VALUES ($1, $2, $3, $4)"+
				" ON CONFLICT (key) DO UPDATE SET"+
				" value = excluded.value, expires = excluded.expires, revision = excluded.revision"+
				" WHERE kv.expires IS NOT NULL AND kv.expires <= now()",
			nonNilKey(i.Key), nonNil(i.Value), zeronull.Timestamptz(i.Expires), revision)
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !created {
		return nil, trace.AlreadyExists("key %q already exists", i.Key)
	}

	i.Revision = revisionToString(revision)
	return backend.NewLease(i), nil
}

// Put implements [backend.Backend].
func (b *Backend) Put(ctx context.Context, i backend.Item) (*backend.Lease, error) {
	revision := newRevision()
	i.Expires = i.Expires.UTC()
	if _, err := pgcommon.Retry(ctx, b.log, func() (struct{}, error) {
		_, err := b.pool.Exec(ctx,
			"INSERT INTO kv (key, value, expires, revision) VALUES ($1, $2, $3, $4)"+
				" ON CONFLICT (key) DO UPDATE SET"+
				" value = excluded.value, expires = excluded.expires, revision = excluded.revision",
			nonNilKey(i.Key), nonNil(i.Value), zeronull.Timestamptz(i.Expires), revision)
		return struct{}{}, trace.Wrap(err)
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	i.Revision = revisionToString(revision)
	return backend.NewLease(i), nil
}

// CompareAndSwap implements [backend.Backend].
func (b *Backend) CompareAndSwap(ctx context.Context, expected, replaceWith backend.Item) (*backend.Lease, error) {
	if expected.Key.Compare(replaceWith.Key) != 0 {
		return nil, trace.BadParameter("expected and replaceWith keys should match")
	}

	revision := newRevision()
	replaceWith.Expires = replaceWith.Expires.UTC()
	swapped, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"UPDATE kv SET value = $1, expires = $2, revision = $3"+
				" WHERE kv.key = $4 AND kv.value = $5 AND (kv.expires IS NULL OR kv.expires > now())",
			nonNil(replaceWith.Value), zeronull.Timestamptz(replaceWith.Expires), revision,
			nonNilKey(replaceWith.Key), nonNil(expected.Value))
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !swapped {
		return nil, trace.CompareFailed("key %q does not exist or does not match expected", replaceWith.Key)
	}

	replaceWith.Revision = revisionToString(revision)
	return backend.NewLease(replaceWith), nil
}

// Update implements [backend.Backend].
func (b *Backend) Update(ctx context.Context, i backend.Item) (*backend.Lease, error) {
	revision := newRevision()
	i.Expires = i.Expires.UTC()
	updated, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"UPDATE kv SET value = $1, expires = $2, revision = $3"+
				" WHERE kv.key = $4 AND (kv.expires IS NULL OR kv.expires > now())",
			nonNil(i.Value), zeronull.Timestamptz(i.Expires), revision, nonNilKey(i.Key))
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !updated {
		return nil, trace.NotFound("key %q does not exist", i.Key)
	}

	i.Revision = revisionToString(revision)
	return backend.NewLease(i), nil
}

func (b *Backend) ConditionalUpdate(ctx context.Context, i backend.Item) (*backend.Lease, error) {
	expectedRevision, ok := revisionFromString(i.Revision)
	if !ok {
		return nil, trace.Wrap(backend.ErrIncorrectRevision)
	}

	newRevision := newRevision()
	i.Expires = i.Expires.UTC()
	updated, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"UPDATE kv SET value = $1, expires = $2, revision = $3 "+
				"WHERE kv.key = $4 AND kv.revision = $5 AND "+
				"(kv.expires IS NULL OR kv.expires > now())",
			nonNil(i.Value), zeronull.Timestamptz(i.Expires), newRevision,
			nonNilKey(i.Key), expectedRevision)
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !updated {
		return nil, trace.Wrap(backend.ErrIncorrectRevision)
	}

	i.Revision = revisionToString(newRevision)
	return backend.NewLease(i), nil
}

// Get implements [backend.Backend].
func (b *Backend) Get(ctx context.Context, key backend.Key) (*backend.Item, error) {
	item, err := pgcommon.RetryIdempotent(ctx, b.log, func() (*backend.Item, error) {
		batch := new(pgx.Batch)
		// batches run in an implicit transaction
		batch.Queue("SET transaction_read_only TO on")

		var item *backend.Item
		batch.Queue("SELECT kv.value, kv.expires, kv.revision FROM kv"+
			" WHERE kv.key = $1 AND (kv.expires IS NULL OR kv.expires > now())", nonNilKey(key),
		).QueryRow(func(row pgx.Row) error {
			var value []byte
			var expires time.Time
			var revision revision
			if err := row.Scan(&value, (*zeronull.Timestamptz)(&expires), &revision); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil
				}
				return trace.Wrap(err)
			}

			item = &backend.Item{
				Key:      key,
				Value:    value,
				Expires:  expires.UTC(),
				Revision: revisionToString(revision),
			}
			return nil
		})

		if err := b.pool.SendBatch(ctx, batch).Close(); err != nil {
			return nil, trace.Wrap(err)
		}

		return item, nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if item == nil {
		return nil, trace.NotFound("key %q does not exist", key)
	}
	return item, nil
}

func (b *Backend) Items(ctx context.Context, params backend.IterateParams) iter.Seq2[backend.Item, error] {
	if params.StartKey.IsZero() {
		err := trace.BadParameter("missing parameter startKey")
		return func(yield func(backend.Item, error) bool) { yield(backend.Item{}, err) }
	}
	if params.EndKey.IsZero() {
		err := trace.BadParameter("missing parameter endKey")
		return func(yield func(backend.Item, error) bool) { yield(backend.Item{}, err) }
	}

	limit := params.Limit
	if limit <= 0 {
		limit = backend.DefaultRangeLimit
	}

	const (
		queryAsc = "SELECT kv.key, kv.value, kv.expires, kv.revision FROM kv" +
			" WHERE kv.key BETWEEN $1 AND $2 AND ($3::bytea is NULL or kv.key > $3) AND (kv.expires IS NULL OR kv.expires > now())" +
			" ORDER BY kv.key ASC LIMIT $4"

		queryDesc = "SELECT kv.key, kv.value, kv.expires, kv.revision FROM kv" +
			" WHERE kv.key BETWEEN $1 AND $2 AND ($3::bytea is NULL or kv.key < $3) AND (kv.expires IS NULL OR kv.expires > now())" +
			" ORDER BY kv.key DESC LIMIT $4"

		defaultPageSize = 1000
	)
	return func(yield func(backend.Item, error) bool) {
		var exclusiveStartKey []byte
		query := queryAsc
		if params.Descending {
			query = queryDesc
		}

		var totalCount int
		for {
			pageLimit := min(limit-totalCount, defaultPageSize)

			items, err := pgcommon.RetryIdempotent(ctx, b.log, func() ([]backend.Item, error) {
				batch := new(pgx.Batch)
				// batches run in an implicit transaction
				batch.Queue("SET transaction_read_only TO on")
				// TODO(espadolini): figure out if we want transaction_deferred enabled
				var items []backend.Item
				batch.Queue(query, nonNilKey(params.StartKey), nonNilKey(params.EndKey), exclusiveStartKey, pageLimit).Query(func(rows pgx.Rows) error {
					var err error
					items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (backend.Item, error) {
						var key backend.Key
						var value []byte
						var expires time.Time
						var revision revision
						if err := row.Scan(&key, &value, (*zeronull.Timestamptz)(&expires), &revision); err != nil {
							return backend.Item{}, err
						}
						return backend.Item{
							Key:      key,
							Value:    value,
							Expires:  expires.UTC(),
							Revision: revisionToString(revision),
						}, nil
					})
					return trace.Wrap(err)
				})

				if err := b.pool.SendBatch(ctx, batch).Close(); err != nil {
					return nil, trace.Wrap(err)
				}

				return items, nil
			})
			if err != nil {
				yield(backend.Item{}, trace.Wrap(err))
				return
			}

			if len(items) >= pageLimit {
				exclusiveStartKey = []byte(items[len(items)-1].Key.String())
			}

			for _, item := range items {
				if !yield(item, nil) {
					return
				}

				totalCount++
				if limit != backend.NoLimit && totalCount >= limit {
					return
				}
			}

			if len(items) < pageLimit {
				return
			}
		}
	}
}

// GetRange implements [backend.Backend].
func (b *Backend) GetRange(ctx context.Context, startKey, endKey backend.Key, limit int) (*backend.GetResult, error) {
	var result backend.GetResult
	for item, err := range b.Items(ctx, backend.IterateParams{StartKey: startKey, EndKey: endKey, Limit: limit}) {
		if err != nil {
			return nil, trace.Wrap(err)
		}

		result.Items = append(result.Items, item)
	}

	return &result, nil
}

// Delete implements [backend.Backend].
func (b *Backend) Delete(ctx context.Context, key backend.Key) error {
	deleted, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"DELETE FROM kv WHERE kv.key = $1 AND (kv.expires IS NULL OR kv.expires > now())", nonNilKey(key))
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if !deleted {
		return trace.NotFound("key %q does not exist", key)
	}
	return nil
}

func (b *Backend) ConditionalDelete(ctx context.Context, key backend.Key, rev string) error {
	expectedRevision, ok := revisionFromString(rev)
	if !ok {
		return trace.Wrap(backend.ErrIncorrectRevision)
	}

	deleted, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"DELETE FROM kv WHERE kv.key = $1 AND kv.revision = $2 AND "+
				"(kv.expires IS NULL OR kv.expires > now())",
			nonNilKey(key), expectedRevision)
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if !deleted {
		return trace.Wrap(backend.ErrIncorrectRevision)
	}
	return nil
}

// DeleteRange implements [backend.Backend].
func (b *Backend) DeleteRange(ctx context.Context, startKey, endKey backend.Key) error {
	// this is the only backend operation that might affect a disproportionate
	// amount of rows at the same time; in actual operation, DeleteRange hardly
	// ever deletes more than dozens of items at once, and logical decoding
	// starts having performance issues when a transaction affects _thousands_
	// of rows at once, so we're good here (but see [Backend.backgroundExpiry])
	if _, err := pgcommon.Retry(ctx, b.log, func() (struct{}, error) {
		_, err := b.pool.Exec(ctx,
			"DELETE FROM kv WHERE kv.key BETWEEN $1 AND $2",
			nonNilKey(startKey), nonNilKey(endKey),
		)
		return struct{}{}, trace.Wrap(err)
	}); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// KeepAlive implements [backend.Backend].
func (b *Backend) KeepAlive(ctx context.Context, lease backend.Lease, expires time.Time) error {
	revision := newRevision()
	updated, err := pgcommon.Retry(ctx, b.log, func() (bool, error) {
		tag, err := b.pool.Exec(ctx,
			"UPDATE kv SET expires = $1, revision = $2"+
				" WHERE kv.key = $3 AND (kv.expires IS NULL OR kv.expires > now())",
			zeronull.Timestamptz(expires.UTC()), revision, nonNilKey(lease.Key))
		if err != nil {
			return false, trace.Wrap(err)
		}
		return tag.RowsAffected() > 0, nil
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if !updated {
		return trace.NotFound("key %q does not exist", lease.Key)
	}
	return nil
}

// NewWatcher implements [backend.Backend].
func (b *Backend) NewWatcher(ctx context.Context, watch backend.Watch) (backend.Watcher, error) {
	return b.buf.NewWatcher(ctx, watch)
}

// CloseWatchers implements [backend.Backend].
func (b *Backend) CloseWatchers() { b.buf.Clear() }

// Clock implements [backend.Backend].
func (b *Backend) Clock() clockwork.Clock {
	// we don't support a custom clock, because deciding which items still exist
	// in the backend depends on which items are still stored but expired, and
	// it's much cleaner to just rely on the server transaction time (which is
	// shared between all auth servers) for that
	return clockwork.NewRealClock()
}
