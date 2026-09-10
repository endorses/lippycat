# Synthetic RADIUS acceptance fixtures

The test fixture generator and independent wire checker now live in
[`internal/pkg/testutil/radiusfixture`](../../internal/pkg/testutil/radiusfixture/README.md).
Tests generate captures and raw messages in temporary directories with
`radiusfixture.Write(t)`. No PCAP or raw binary fixtures are stored in the repository.
