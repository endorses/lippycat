package detector

import "testing"

func BenchmarkGenerateFlowID(b *testing.B) {
	b.Run("IPv4_TCP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = generateFlowID("192.0.2.10", "198.51.100.20", 49152, 443, "TCP")
		}
	})
	b.Run("IPv6_UDP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = generateFlowID("2001:db8::10", "2001:db8:1::20", 49152, 5060, "UDP")
		}
	})
}
