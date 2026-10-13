package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func ref(n int) OfferRef {
	return OfferRef{JobID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), Attempt: fmt.Sprintf("00000000-0000-4000-9000-%012d", n)}
}

// The record keeps each canonical offer once, in arrival order, drops the
// oldest past 64, hands everything over and empties on take, and puts back
// what an unanswered heartbeat carried ahead of newer offers.
func TestOffersSeenAccumulatesDedupsCapsAndClears(t *testing.T) {
	var s offersSeen
	if got := s.take(); got == nil || len(got) != 0 {
		t.Fatalf("empty take %#v", got)
	}
	if raw, _ := json.Marshal(Heartbeat{OffersSeen: s.take()}); !strings.Contains(string(raw), `"offers_seen":[]`) {
		t.Fatalf("empty acknowledgements on the wire: %s", raw)
	}
	s.record(ref(1), ref(2), ref(1))
	s.record(ref(2), ref(3))
	// Identifiers the coordinator never issues are left out: an uppercase or
	// braced UUID, the nil UUID, an opaque legacy ID and an empty one.
	upper := OfferRef{JobID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", Attempt: ref(4).Attempt}
	s.record(upper, OfferRef{JobID: uuid.Nil.String(), Attempt: ref(5).Attempt}, OfferRef{JobID: "synthetic", Attempt: "1"}, OfferRef{}, OfferRef{JobID: "{" + ref(6).JobID + "}", Attempt: ref(6).Attempt})
	if got := s.take(); !reflect.DeepEqual(got, []OfferRef{ref(1), ref(2), ref(3)}) {
		t.Fatalf("recorded %v", got)
	}
	if got := s.take(); len(got) != 0 {
		t.Fatalf("take did not clear: %v", got)
	}
	for n := 1; n <= 70; n++ {
		s.record(ref(n))
	}
	got := s.take()
	if len(got) != MaxOffersSeen || got[0] != ref(7) || got[MaxOffersSeen-1] != ref(70) {
		t.Fatalf("cap kept %d from %v to %v", len(got), got[0], got[len(got)-1])
	}
	// An unanswered heartbeat's acknowledgements go first next time, once.
	s.record(ref(100))
	s.restore([]OfferRef{ref(98), ref(99), ref(100)})
	if got := s.take(); !reflect.DeepEqual(got, []OfferRef{ref(98), ref(99), ref(100)}) {
		t.Fatalf("restored %v", got)
	}
}

type heartbeatServer struct {
	mu      sync.Mutex
	seen    [][]OfferRef
	raw     []string
	answers []func(http.ResponseWriter)
}

func (s *heartbeatServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var h Heartbeat
	if r.URL.Path != "/api/node/v1/heartbeat" || json.Unmarshal(raw, &h) != nil {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	s.mu.Lock()
	n := len(s.seen)
	s.seen = append(s.seen, h.OffersSeen)
	s.raw = append(s.raw, string(raw))
	answer := func(w http.ResponseWriter) {
		io.WriteString(w, `{"leases":[],"node":{"missed_streak":0,"suspect_until":null}}`)
	}
	if n < len(s.answers) {
		answer = s.answers[n]
	}
	s.mu.Unlock()
	answer(w)
}

func leaseJSON(t *testing.T, n int) json.RawMessage {
	t.Helper()
	l := Lease{Version: Version, ServiceType: "web", JobID: ref(n).JobID, Attempt: ref(n).Attempt, Fence: fmt.Sprintf("00000000-0000-4000-a000-%012d", n), AcceptanceRequired: true}
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Every offer in a decoded answer is acknowledged on the next heartbeat, an
// offer that does not decode included; a heartbeat that is not answered hands
// its acknowledgements to the one after it, and an answered one clears them.
func TestPollAcknowledgesOffersOnTheNextHeartbeat(t *testing.T) {
	unreadable := fmt.Sprintf(`{"version":%q,"job_id":%q,"attempt":%q,"fence":"00000000-0000-4000-a000-000000000003","lease_deadline":"tomorrow"}`, Version, ref(3).JobID, ref(3).Attempt)
	server := &heartbeatServer{answers: []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			fmt.Fprintf(w, `{"leases":[%s,%s,%s,%s],"node":{"missed_streak":2,"suspect_until":"2026-10-11T22:00:30Z"}}`, leaseJSON(t, 1), leaseJSON(t, 2), leaseJSON(t, 1), unreadable)
		},
		func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()
	c := New(ts.URL, "demo")
	reply, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Leases) != 3 || reply.Leases[0].JobID != ref(1).JobID || reply.Leases[1].JobID != ref(2).JobID || reply.Leases[2].JobID != ref(1).JobID {
		t.Fatalf("leases %+v", reply.Leases)
	}
	if want := []OfferAttempt{{JobID: ref(3).JobID, Attempt: ref(3).Attempt, Fence: "00000000-0000-4000-a000-000000000003"}}; !reflect.DeepEqual(reply.Unreadable, want) {
		t.Fatalf("unreadable %+v", reply.Unreadable)
	}
	if reply.Node == nil || reply.Node.MissedStreak != 2 || reply.Node.SuspectUntil == nil || reply.Node.SuspectUntil.UTC().Format("15:04:05") != "22:00:30" {
		t.Fatalf("node health %+v", reply.Node)
	}
	acks := []OfferRef{ref(1), ref(2), ref(3)}
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"}); err == nil {
		t.Fatal("500 answered")
	}
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.seen[0]) != 0 || !reflect.DeepEqual(server.seen[1], acks) || !reflect.DeepEqual(server.seen[2], acks) || len(server.seen[3]) != 0 {
		t.Fatalf("offers_seen per heartbeat %v", server.seen)
	}
	for i, raw := range server.raw {
		if !strings.Contains(raw, `"offers_seen":[`) || strings.Contains(raw, `"offers_seen":null`) {
			t.Fatalf("heartbeat %d without offers_seen: %s", i, raw)
		}
	}
}

// An answer may carry eight leases of the largest size the node accepts for
// one; the heartbeat fixture's two offers and node health decode as written.
func TestPollReadsSeveralFullLeases(t *testing.T) {
	big := strings.Repeat("p", 100<<10)
	var leases []string
	for n := 1; n <= MaxLeasesPerReply; n++ {
		l := Lease{Version: Version, ServiceType: "codex", JobID: ref(n).JobID, Attempt: ref(n).Attempt, Fence: ref(n).Attempt, Prompt: big, AcceptanceRequired: true}
		raw, _ := json.Marshal(l)
		leases = append(leases, string(raw))
	}
	fixture, err := os.ReadFile("../../api/fixtures/heartbeat-reply.json")
	if err != nil {
		t.Fatal(err)
	}
	server := &heartbeatServer{answers: []func(http.ResponseWriter){
		func(w http.ResponseWriter) { io.WriteString(w, `{"leases":[`+strings.Join(leases, ",")+`]}`) },
		func(w http.ResponseWriter) { w.Write(fixture) },
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()
	c := New(ts.URL, "demo")
	reply, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
	if err != nil || len(reply.Leases) != MaxLeasesPerReply || reply.Leases[7].Prompt != big {
		t.Fatalf("eight full leases: %d, %v", len(reply.Leases), err)
	}
	reply, err = c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
	if err != nil || len(reply.Leases) != 2 || reply.Leases[1].Fence != "66666666-6666-4666-8666-666666666666" || reply.Node == nil || reply.Node.MissedStreak != 1 || len(reply.Unreadable) != 0 {
		t.Fatalf("fixture reply %+v %v", reply, err)
	}
}

// A rejection names the attempt, fence and reason of an offer never accepted,
// on the job's reject route; 409 attempt_conflict is reported with its code.
func TestRejectSendsTheAttemptAndReason(t *testing.T) {
	type call struct {
		path string
		body map[string]string
	}
	calls := make(chan call, 4)
	conflict := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer demo" || r.Header.Get(NodeVersionHeader) != NodeRelease || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("unauthenticated or malformed rejection")
		}
		calls <- call{r.URL.Path, body}
		if conflict {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":{"code":"attempt_conflict","message":"That attempt cannot accept this report."}}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := New(ts.URL, "demo")
	offer := OfferAttempt{JobID: ref(1).JobID, Attempt: ref(1).Attempt, Fence: "00000000-0000-4000-a000-000000000001"}
	if err := c.Reject(context.Background(), offer, RejectNoSlot); err != nil {
		t.Fatal(err)
	}
	got := <-calls
	if got.path != "/api/node/v1/jobs/"+offer.JobID+"/reject" || !reflect.DeepEqual(got.body, map[string]string{"version": Version, "attempt": offer.Attempt, "fence": offer.Fence, "reason": "no_slot"}) {
		t.Fatalf("rejection %+v", got)
	}
	conflict = true
	var status *StatusError
	if err := c.Reject(context.Background(), offer, RejectInvalidOffer); !errors.As(err, &status) || status.Status != http.StatusConflict || status.Code != "attempt_conflict" {
		t.Fatalf("conflict reported as %v", err)
	}
	<-calls
	if err := c.Reject(context.Background(), OfferAttempt{JobID: "../escape"}, RejectOther); err == nil {
		t.Fatal("invalid job ID sent")
	}
	select {
	case extra := <-calls:
		t.Fatalf("invalid job ID reached the coordinator: %+v", extra)
	default:
	}
	if got := c.Stats().Rejections; got != 2 {
		t.Fatalf("%d rejections counted, want the 2 sent", got)
	}
	if (Lease{JobID: "j", Attempt: "a", Fence: "f"}).OfferAttempt() != (OfferAttempt{JobID: "j", Attempt: "a", Fence: "f"}) {
		t.Fatal("lease identity")
	}
}
