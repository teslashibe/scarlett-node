package x

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidAuth   = errors.New("x: missing required cookie (auth_token or ct0)")
	ErrUnauthorized  = errors.New("x: authentication failed — session may be expired")
	ErrForbidden     = errors.New("x: access denied (protected account or private resource)")
	ErrNotFound      = errors.New("x: resource not found")
	ErrSuspended     = errors.New("x: account is suspended")
	ErrRateLimited   = errors.New("x: rate limited")
	ErrQueryIDStale  = errors.New("x: queryId is stale — use WithQueryIDs or RefreshQueryIDs")
	ErrInvalidParams = errors.New("x: invalid or missing required parameters")
	ErrPartialResult = errors.New("x: context cancelled; partial result returned")
	ErrRequestFailed = errors.New("x: HTTP request failed")

	ErrAlreadyRetweeted  = errors.New("x: tweet already retweeted")
	ErrTweetTooLong      = errors.New("x: tweet text exceeds account character limit")
	ErrDMClosed          = errors.New("x: recipient has DMs closed")
	ErrChallenge         = errors.New("x: additional verification required")
	ErrDefinite          = errors.New("x: request definitely did not complete")
	ErrAmbiguous         = errors.New("x: request outcome is ambiguous")
	errWriteNotAttempted = errors.New("x: write was not attempted")

	ErrUnsupportedMediaType = errors.New("x: unsupported media type")
	ErrMediaTooLarge        = errors.New("x: media exceeds the maximum allowed size")

	ErrMediaProcessingFailed  = errors.New("x: media processing failed")
	ErrMediaProcessingTimeout = errors.New("x: media processing did not complete in time")
)

// OperationError retains bounded, non-secret evidence about a failed provider
// operation. It deliberately excludes request URLs, query IDs, variables,
// response bodies, cookies, identities, and proxy details.
type OperationError struct {
	Operation              string
	Status                 int
	ContentType            string
	TransactionIDAttached  bool
	TransactionReady       bool
	QueryMetadataRefreshed bool
	Err                    error
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("x: %s failed: %v", e.Operation, e.Err)
}

func (e *OperationError) Unwrap() error { return e.Err }

// OutcomeError classifies whether a failed write definitely did not complete
// or may have completed before the transport failed.
type OutcomeError struct {
	Outcome error
	Err     error
}

func (e *OutcomeError) Error() string { return e.Outcome.Error() + ": " + e.Err.Error() }
func (e *OutcomeError) Unwrap() []error {
	return []error{e.Outcome, e.Err}
}

func classifyWriteOutcome(err error) error {
	if err == nil {
		return nil
	}
	outcome := ErrAmbiguous
	if errors.Is(err, ErrInvalidParams) ||
		errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrSuspended) ||
		errors.Is(err, ErrRateLimited) ||
		errors.Is(err, ErrChallenge) ||
		errors.Is(err, ErrDMClosed) ||
		errors.Is(err, ErrTweetTooLong) ||
		errors.Is(err, ErrQueryIDStale) ||
		errors.Is(err, errWriteNotAttempted) {
		outcome = ErrDefinite
	}
	return &OutcomeError{Outcome: outcome, Err: err}
}
