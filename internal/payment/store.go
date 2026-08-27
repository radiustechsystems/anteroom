package payment

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var grantsBucket = []byte("grants-v1")

const paymentLease = 30 * time.Second

// Grant is the durable result of one settled payment. ExpiresAt limits the
// entitlement. The record itself has no expiry because the underlying chain
// nonce is single-use: forgetting it would let a cached facilitator success buy
// another entitlement.
type Grant struct {
	Scope       string `json:"scope"`
	Audience    string `json:"audience"`
	Payer       string `json:"payer,omitempty"`
	Transaction string `json:"transaction"`
	Amount      string `json:"amount,omitempty"`
	Network     string `json:"network"`
	ExpiresAt   int64  `json:"expires_at"`
}

type grantRecord struct {
	Lease        string `json:"lease,omitempty"`
	PendingUntil int64  `json:"pending_until,omitempty"`
	Grant        *Grant `json:"grant,omitempty"`
}

// BeginResult classifies a durable claim lookup.
type BeginResult int

const (
	BeginNew BeginResult = iota
	BeginInFlight
	BeginRecoverable
	BeginSpent
)

// GrantStore serializes payment claims through a small bbolt file. The file is
// opened only for an operation: payment is a cold path, and short opens let
// multiple Anteroom processes coordinate through the same local volume instead
// of one process holding bbolt's exclusive file lock for its lifetime.
type GrantStore struct {
	path string
	now  func() time.Time
}

// NewGrantStore creates or checks the store before the gate accepts traffic.
func NewGrantStore(path string) (*GrantStore, error) {
	if path == "" {
		return nil, errors.New("payment: state_file is empty")
	}
	s := &GrantStore{path: path, now: time.Now}
	if err := s.update(func(b *bolt.Bucket) error { return nil }); err != nil {
		return nil, fmt.Errorf("payment: open state file %q: %w", path, err)
	}
	return s, nil
}

func (s *GrantStore) open() (*bolt.DB, error) {
	return bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
}

func (s *GrantStore) update(fn func(*bolt.Bucket) error) error {
	db, err := s.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(grantsBucket)
		if err != nil {
			return err
		}
		return fn(b)
	})
}

func decodeGrantRecord(raw []byte) (grantRecord, error) {
	var rec grantRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("payment: corrupt grant record: %w", err)
	}
	if rec.Grant != nil {
		if rec.Lease != "" || rec.PendingUntil != 0 {
			return rec, errors.New("payment: corrupt grant record: committed grant has a lease")
		}
		if err := validateGrant(*rec.Grant); err != nil {
			return rec, fmt.Errorf("payment: corrupt grant record: %w", err)
		}
	} else if rec.Lease == "" || rec.PendingUntil <= 0 {
		return rec, errors.New("payment: corrupt grant record: incomplete reservation")
	}
	return rec, nil
}

func validateGrant(grant Grant) error {
	if grant.Scope == "" || grant.Audience == "" || grant.Transaction == "" ||
		grant.Network == "" || grant.ExpiresAt <= 0 {
		return errors.New("incomplete grant")
	}
	return nil
}

func encodeGrantRecord(rec grantRecord) ([]byte, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("payment: encode grant record: %w", err)
	}
	return raw, nil
}

func newLease() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("payment: lease entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// Begin atomically reserves an unseen payment, reports an in-flight attempt,
// or returns the grant already bought by this authorization. The caller must
// Release a new lease unless it successfully Commits it.
func (s *GrantStore) Begin(id string) (BeginResult, string, Grant, error) {
	if id == "" {
		return BeginSpent, "", Grant{}, errors.New("payment: empty payment ID")
	}
	now := s.now()
	var lease string
	result := BeginNew
	var existing Grant
	err := s.update(func(b *bolt.Bucket) error {
		raw := b.Get([]byte(id))
		if raw != nil {
			rec, err := decodeGrantRecord(raw)
			if err != nil {
				return err
			}
			if rec.Grant != nil {
				existing = *rec.Grant
				if now.Unix() < rec.Grant.ExpiresAt {
					result = BeginRecoverable
				} else {
					result = BeginSpent
				}
				return nil
			}
			if rec.Grant == nil && now.UnixNano() < rec.PendingUntil {
				result = BeginInFlight
				return nil
			}
		}
		var err error
		lease, err = newLease()
		if err != nil {
			return err
		}
		rec := grantRecord{Lease: lease, PendingUntil: now.Add(paymentLease).UnixNano()}
		enc, err := encodeGrantRecord(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), enc)
	})
	if err != nil {
		return BeginSpent, "", Grant{}, err
	}
	if result != BeginNew {
		lease = ""
	}
	return result, lease, existing, nil
}

// Release removes the caller's still-pending reservation. Matching the random
// lease prevents a late defer from deleting a newer attempt's reservation.
func (s *GrantStore) Release(id, lease string) error {
	if lease == "" {
		return nil
	}
	return s.update(func(b *bolt.Bucket) error {
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		rec, err := decodeGrantRecord(raw)
		if err != nil {
			return err
		}
		if rec.Grant == nil && rec.Lease == lease {
			return b.Delete([]byte(id))
		}
		return nil
	})
}

// Commit atomically replaces the caller's reservation with a durable grant.
// An existing committed grant wins, so racing processes converge on one result.
func (s *GrantStore) Commit(id, lease string, grant Grant) (Grant, bool, error) {
	if err := validateGrant(grant); err != nil {
		return Grant{}, false, fmt.Errorf("payment: %w", err)
	}
	created := false
	result := grant
	err := s.update(func(b *bolt.Bucket) error {
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("payment: grant reservation disappeared")
		}
		rec, err := decodeGrantRecord(raw)
		if err != nil {
			return err
		}
		if rec.Grant != nil {
			result = *rec.Grant
			return nil
		}
		if lease == "" || rec.Lease != lease {
			return errors.New("payment: grant reservation changed")
		}
		enc, err := encodeGrantRecord(grantRecord{Grant: &grant})
		if err != nil {
			return err
		}
		created = true
		return b.Put([]byte(id), enc)
	})
	return result, created, err
}
