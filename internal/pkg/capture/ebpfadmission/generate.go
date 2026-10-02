package ebpfadmission

// Generate both byte orders; checked-in objects are used by ordinary builds.
// Requires clang with BPF target and libbpf development headers.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -no-strip admission bpf/admission.c -- -O2 -g -Wall -Werror
