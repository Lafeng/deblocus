package geo

/*
http://www.drdobbs.com/windows/fast-ip-routing-with-lc-tries/184410638
https://raw.githubusercontent.com/kbandla/lctrie/master/docs/paper.pdf
*/

import (
	"reflect"
	"sort"
)

const UseNexthopCompression = false

var (
	ROOTBRANCH uint32  = 16   // The branching factor at the root
	FILLFACT   float64 = 0.50 // The trie fill factor
)

func buildRoutingTable(entries entrySet) *routingTable {
	var (
		//nexthop sort.Interface /* Nexthop table */
		nprefs, nbases uint32
		nextfree       uint32 = 1
		esLen, size           = entries.Len2()
	)

	sort.Stable(entries)
	/*
		if UseNexthopCompression {
			nexthop = buildnexthoptable(entries)
		}
	*/
	// Size after dublicate removal
	// Remove duplicates
	for i := 1; i < esLen; i++ {
		if pstrcmp(entries[i-1], entries[i]) != 0 {
			entries[size] = entries[i]
			size++
		}
	}

	/* The number of internal nodes in the tree can't be larger
	   than the number of entries. */
	t := make([]uint32, 2*size+2000000)
	b := make([]*base_t, size)
	p := make([]*pre_t, size)

	/* Initialize pre-pointers */
	for i := 0; i < size; i++ {
		entries[i].pre = NOPRE
	}

	/* Go through the entries and put the prefixes in p
	   and the rest of the strings in b */
	for i := 0; i < size; i++ {
		if i < size-1 && isprefix(entries[i], entries[i+1]) {
			ptemp := new(pre_t)
			ptemp.len = entries[i].len
			ptemp.pre = entries[i].pre
			/* Update 'pre' for all entries that have this prefix */
			for j := i + 1; j < size && isprefix(entries[i], entries[j]); j++ {
				entries[j].pre = int(nprefs)
			}
			// if UseNexthopCompression then
			// ptemp.nexthop = sort.SearchInts(nexthop, entries[i].nexthop)
			ptemp.nexthop = entries[i].nexthop
			p[nprefs] = ptemp
			nprefs++
		} else {
			btemp := new(base_t)
			btemp.len = entries[i].len
			btemp.str = entries[i].data
			btemp.pre = entries[i].pre
			// if UseNexthopCompression then
			// btemp.nexthop = sort.SearchInts(nexthop, entries[i].nexthop)
			btemp.nexthop = entries[i].nexthop
			b[nbases] = btemp
			nbases++
		}
	}
	/* Build the trie structure */
	buildTrie(b, p, 0, 0, nbases, 0, &nextfree, t)

	/* At this point we now how much memory to allocate */
	trie := make([]uint32, nextfree)
	base := make([]base_t, nbases)
	pre := make([]pre_t, nprefs)

	for i := uzero; i < nextfree; i++ {
		trie[i] = t[i]
	}
	t = nil //free(t)

	for i := uzero; i < nbases; i++ {
		base[i] = *b[i]
	}
	b = nil //free(b)

	for i := uzero; i < nprefs; i++ {
		pre[i] = *p[i]
	}
	p = nil //free(p)

	return &routingTable{
		trie: trie,
		base: base,
		pre:  pre,
		//		nexthop: nexthop,
	}
}

/* Return a nexthop or 0 if not found */
func (t *routingTable) Find(s uint32) (interface{}, bool) {
	var pos, branch, adr, node, bitmask uint32
	/* Traverse the trie */
	node = t.trie[0]
	pos = GETSKIP(node)
	branch = GETBRANCH(node)
	adr = GETADR(node)

	for branch != 0 {
		node = t.trie[adr+EXTRACT(pos, branch, s)]
		pos += branch + GETSKIP(node)
		branch = GETBRANCH(node)
		adr = GETADR(node)
	}

	/* Was this a hit? */
	bitmask = t.base[adr].str ^ s
	if EXTRACT(0, t.base[adr].len, bitmask) == 0 {
		// if UseNexthopCompression then
		// t->nexthop[t->base[adr].nexthop];
		return t.base[adr].nexthop, true
	}

	/* If not, look in the prefix tree
	 */
	preadr := t.base[adr].pre
	for preadr != NOPRE {
		if EXTRACT(0, t.pre[preadr].len, bitmask) == 0 {
			// if UseNexthopCompression then
			// t->nexthop[t->pre[preadr].nexthop];
			return t.pre[preadr].nexthop, true
		}
		preadr = t.pre[preadr].pre
	}

	return nil, false /* Not found */
}

/*
   Build a tree that covers the base array from position
   'first' to 'first + n - 1'. Disregard the first 'prefix'
   characters. 'pos' is the position for the root of this
   tree and 'nextfree' is the first position in the array
   that hasn't yet been reserved.
*/
func buildTrie(base []*base_t, pre []*pre_t, prefix, first, n, pos uint32, nextfree *uint32, tree []uint32) {
	var (
		p, k, branch, newprefix uint32
		bits, adr, bitpat       uint32
	)

	if n == 1 {
		tree[pos] = first /* branch and skip are 0 */
	} else {
		branch, newprefix = computeBranch(base, prefix, first, n)

		adr = *nextfree
		tree[pos] = SETBRANCH(branch) | SETSKIP(newprefix-prefix) | adr
		*nextfree += 1 << branch
		p = first
		/* Build the subtrees */
		for bitpat = 0; bitpat < 1<<branch; bitpat++ {
			k = 0
			for p+k < first+n && EXTRACT(newprefix, branch, base[p+k].str) == bitpat {
				k++
			}

			if k == 0 {
				/* The leaf should have a pointer either to p-1 or p,
				   whichever has the longest matching prefix */
				var match1, match2 uint32

				/* Compute the longest prefix match for p - 1 */
				if p > first {
					var prep = base[p-1].pre
					var _len uint32
					for prep != NOPRE && match1 == 0 {
						_len = pre[prep].len
						if _len > newprefix && EXTRACT(newprefix, _len-newprefix, base[p-1].str) == EXTRACT(32-branch, _len-newprefix, bitpat) {
							match1 = _len
						} else {
							prep = pre[prep].pre
						}
					}
				}

				/* Compute the longest prefix match for p */
				if p < first+n {
					var prep = base[p].pre
					var _len uint32
					for prep != NOPRE && match2 == 0 {
						_len = pre[prep].len
						if _len > newprefix && EXTRACT(newprefix, _len-newprefix, base[p].str) == EXTRACT(32-branch, _len-newprefix, bitpat) {
							match2 = _len
						} else {
							prep = pre[prep].pre
						}
					}
				}
				if (match1 > match2 && p > first) || p == first+n {
					buildTrie(base, pre, newprefix+branch, p-1, 1, adr+bitpat, nextfree, tree)
				} else {
					buildTrie(base, pre, newprefix+branch, p, 1, adr+bitpat, nextfree, tree)
				}
			} else if k == 1 && base[p].len-newprefix < branch {
				bits = branch - base[p].len + newprefix
				for i := bitpat; i < bitpat+(1<<bits); i++ {
					buildTrie(base, pre, newprefix+branch, p, 1, adr+i, nextfree, tree)
				}
				bitpat += (1 << bits) - 1
			} else {
				buildTrie(base, pre, newprefix+branch, p, k, adr+bitpat, nextfree, tree)
			}
			p += k
		}

	}
}

/*
   Compute the branch and skip value for the root of the
   tree that covers the base array from position 'first' to
   'first + n - 1'. Disregard the first 'prefix' characters.
   We assume that n >= 2 and base[first] != base[first+n-1].
*/
func computeBranch(base []*base_t, prefix, first, n uint32) (branch, newprefix uint32) {
	var low, high, pat, count uint32
	/* Compute the new prefix */
	high = REMOVE(prefix, base[first].str)
	low = REMOVE(prefix, base[first+n-1].str)

	var i = prefix
	for EXTRACT(i, 1, low) == EXTRACT(i, 1, high) {
		i++
	}
	newprefix = i

	/* Always use branching factor 2 for two elements */
	if n == 2 {
		branch = 1
		return
	}

	/* Use a large branching factor at the root */
	if ROOTBRANCH > 0 && prefix == 0 && first == 0 {
		branch = ROOTBRANCH
		return
	}

	/* Compute the number of bits that can be used for branching.
	   We have at least two branches. Therefore we start the search
	   at 2^b = 4 branches. */
	var (
		b        uint32 = 1
		patfound bool
	)
	for b == 1 || float64(count) >= leftShiftB_multiply_Fillfact(b) {
		b++
		if float64(n) < leftShiftB_multiply_Fillfact(b) || newprefix+b > ADRSIZE {
			break
		}
		i, pat, count = first, 0, 0
		for pat < 1<<b {
			patfound = false
			for i < first+n && pat == EXTRACT(newprefix, b, base[i].str) {
				i++
				patfound = true
			}
			if patfound {
				count++
			}
			pat++
		}
	}
	branch = b - 1
	return
}

// for building compressed nexthop table
func buildNexthopTable(entry entrySet) sort.Interface {
	first := entry[0].nexthop
	switch reflect.TypeOf(first).Kind() {
	case reflect.Int:
		return buildIntNexthopTable(entry)
	case reflect.String:
		return buildStringNexthopTable(entry)
	}
	return nil
}

func buildIntNexthopTable(entries entrySet) sort.Interface {
	var (
		eLen, count = entries.Len2()
		nexttemp    = make([]int, eLen)
	)
	for i := 0; i < eLen; i++ {
		nexttemp[i] = entries[i].nexthop.(int)
	}
	sort.Ints(nexttemp)
	/* Remove duplicates */
	for i := 1; i < eLen; i++ {
		if nexttemp[i-1] != nexttemp[i] {
			nexttemp[count] = nexttemp[i]
			count++
		}
	}
	/* Move the elements to an array of proper size */
	nexthop := make(sort.IntSlice, count)
	copy(nexthop, nexttemp[:count])
	return nexthop
}

func buildStringNexthopTable(entries entrySet) sort.Interface {
	var (
		eLen, count = entries.Len2()
		nexttemp    = make([]string, eLen)
	)
	for i := 0; i < eLen; i++ {
		nexttemp[i] = entries[i].nexthop.(string)
	}
	sort.Strings(nexttemp)
	/* Remove duplicates */
	for i := 1; i < eLen; i++ {
		if nexttemp[i-1] != nexttemp[i] {
			nexttemp[count] = nexttemp[i]
			count++
		}
	}
	/* Move the elements to an array of proper size */
	nexthop := make(sort.StringSlice, count)
	copy(nexthop, nexttemp[:count])
	return nexthop
}
