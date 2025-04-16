package ecies

// safeConcat concatenates two byte slices into a new slice without modifying the input slices.
// It allocates a new slice with enough capacity to hold both a and b, copies the contents
// of a followed by b into it, and returns the resulting slice.
//
// This is safer than using append(a, b...) when you want to ensure the original slices
// aren't modified if the capacity of a is large enough to hold b.
func safeConcat(a, b []byte) []byte {
	out := make([]byte, len(a)+len(b))
	copy(out, a)
	copy(out[len(a):], b)
	return out
}
