/**
 * A minimalistic, memory size-savvy and fairly fast radix tree (AKA Patricia trie)
 * implementation that uses IPv4 addresses with netmasks as keys and 32-bit signed
 * integers as values.
 *
 * This tree is generally uses in read-only manner: there are no key removal operation
 * and the whole thing works best in pre-allocated fashion.
 */
package geo

const (
	NOPRE   int    = -1 /* an empty prefix pointer */
	ADRSIZE        = 32
	uzero   uint32 = 0
)

type entry struct {
	data    uint32      /* the routing entry */
	len     uint32      /* and its length */
	pre     int         /* this auxiliary variable is used in the */
	nexthop interface{} /* the corresponding next-hop */
} /* construction of the final data structure */

/* base vector */
type base_t struct {
	str     uint32      /* the routing entry */
	len     uint32      /* and its length */
	pre     int         /* pointer to prefix table, -1 if no prefix */
	nexthop interface{} /* pointer to next-hop table */
}

/* prefix vector */
type pre_t struct {
	len     uint32      /* the length of the prefix */
	pre     int         /* pointer to prefix, -1 if no prefix */
	nexthop interface{} /* pointer to nexthop table */
}

/* The complete routing table data structure consists of
   a trie, a base vector, a prefix vector, and a next-hop table. */

//type routtable_t *routtablerec
type routingTable struct {
	trie []uint32 /* the main trie search structure */
	base []base_t /* the base vector */
	pre  []pre_t  /* the prefix vector */
	//	nexthop []interface{} /* the next-hop table */
}

// the next has same prefix as the prev ?
func isprefix(prev, next *entry) bool {
	return prev != nil &&
		// (s.len == 0 || /* EXTRACT() can't handle 0 bits */
		(prev.len <= next.len &&
			EXTRACT(0, prev.len, prev.data) == EXTRACT(0, prev.len, next.data))
}

// sort entrySet
type entrySet []*entry

func (t entrySet) Len() int           { return len(t) }
func (t entrySet) Less(i, j int) bool { return pstrcmp(t[i], t[j]) <= 0 }
func (t entrySet) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }
func (t entrySet) Len2() (_len int, notEmpty int) {
	_len = len(t)
	if _len > 0 {
		notEmpty = 1
	}
	return
}

func pstrcmp(a, b *entry) int {
	if a.data < b.data {
		return -1
	} else if a.data > b.data {
		return 1
	} else if a.len < b.len {
		return -1
	} else if a.len > b.len {
		return 1
	} else {
		return 0
	}
}

// macro
func GETSKIP(node uint32) uint32 {
	return (node) >> 22 & 037
}
func SETSKIP(skip uint32) uint32 {
	return skip << 22
}
func GETBRANCH(node uint32) uint32 {
	return (node) >> 27
}
func SETBRANCH(branch uint32) uint32 {
	return branch << 27
}
func GETADR(node uint32) uint32 {
	return node & 017777777
}

/* extract n bits from str starting at position p */
func EXTRACT(p, n, str uint32) uint32 {
	return str << p >> (32 - n)
}

/* remove the first p bits from string */
func REMOVE(p, str uint32) uint32 {
	return str << p >> p
}

func leftShiftB_multiply_Fillfact(b uint32) float64 {
	b = 1 << b
	return FILLFACT * float64(b)
}
