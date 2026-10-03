//go:build unix

package main

import "testing"

func TestActualCLIDrainFinishesAcceptedWorkAndSurvivesRestart(t *testing.T) {
	testActualCLIDrain(t, false)
}
