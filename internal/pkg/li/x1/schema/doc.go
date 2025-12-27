//go:build li

// Package schema provides Go types generated from ETSI TS 103 221-1 (X1 interface)
// and TS 103 280 (common types) XSD schemas.
//
// These types define the XML structures for X1 protocol messages between
// the ADMF (Administration Function) and NE (Network Element) in lawful
// interception systems.
//
// Source schemas:
//   - TS 103 221-1: X1 interface messages (tasks, destinations, etc.)
//   - TS 103 280: Common types (identifiers, addresses, etc.)
//   - TS 103 221-1 HashedID: Hashed identifier support
//
// Schema source: https://forge.etsi.org/rep/li/schemas-definitions
package schema
