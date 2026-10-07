package webruntime

import "sort"

// procInfo is one row of the process table: identity, parent, process group
// and memory (darwin: RSS; linux: filled per descendant from Pss).
type procInfo struct {
	PID, PPID, PGID int
	Bytes           uint64
	Zombie          bool
}

// descendants is root and every process below it, found by walking parent
// PIDs, never by process group: Playwright starts Chrome detached, so the
// browser leads its own group and the helper's group never reaches it.
func descendants(table []procInfo, root int) []procInfo {
	children := map[int][]procInfo{}
	var out []procInfo
	for _, p := range table {
		children[p.PPID] = append(children[p.PPID], p)
		if p.PID == root {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	seen := map[int]bool{root: true}
	for stack := []int{root}; len(stack) > 0; {
		pid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, child := range children[pid] {
			if !seen[child.PID] {
				seen[child.PID] = true
				out = append(out, child)
				stack = append(stack, child.PID)
			}
		}
	}
	return out
}

// killPlan is every distinct process group and every PID of a snapshot,
// never group 0 or 1 and never the caller's own group.
func killPlan(tree []procInfo, own int) (groups, pids []int) {
	seenGroup := map[int]bool{}
	for _, p := range tree {
		if p.PGID > 1 && p.PGID != own && !seenGroup[p.PGID] {
			seenGroup[p.PGID] = true
			groups = append(groups, p.PGID)
		}
		if p.PID > 1 {
			pids = append(pids, p.PID)
		}
	}
	sort.Ints(groups)
	sort.Ints(pids)
	return groups, pids
}

func sumBytes(tree []procInfo) uint64 {
	var total uint64
	for _, p := range tree {
		total += p.Bytes
	}
	return total
}
