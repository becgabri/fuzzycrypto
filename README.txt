Notes:

This is a Go implementation of the basic fuzzy scheme. Ciphertexts are computed as:

U = rP, y, c_i = H(rPK || CH(v, y)) XOR 1 (for i \in [N])

With CH(v, y) defined as (vP + yU).

----

To run the basic test code:

go run fuzzy.go

To run the benchmarks:

go test -bench=.

The benchmarks specify an 80 bit ciphertext, and perform extraction/testing at N=5, N=10, N=20.

