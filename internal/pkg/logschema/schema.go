// Package logschema contains the versioned, output-neutral schema contract for
// lippycat structured protocol logs. Writers and event-to-record mappers should
// consume this package rather than defining field order independently.
package logschema

// Field describes one structured-log column. Type uses Zeek's log type names.
type Field struct {
	Name string
	Type string
}

// Stream describes a first-release structured log stream.
type Stream struct {
	Name     string
	Filename string
	Fields   []Field
}

// Streams is the canonical first-release stream order and schema registry.
var Streams = []Stream{
	stream("conn", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"proto", "enum"}, {"service", "string"}, {"duration", "interval"}, {"orig_bytes", "count"}, {"resp_bytes", "count"},
		{"conn_state", "string"}, {"local_orig", "bool"}, {"local_resp", "bool"}, {"missed_bytes", "count"}, {"history", "string"},
		{"orig_pkts", "count"}, {"orig_ip_bytes", "count"}, {"resp_pkts", "count"}, {"resp_ip_bytes", "count"},
		{"community_id", "string"}, {"node_id", "string"}, {"capture_scope", "enum"}, {"partial", "bool"},
	}),
	stream("dns", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"proto", "enum"}, {"trans_id", "count"}, {"rtt", "interval"}, {"query", "string"}, {"qclass", "count"}, {"qclass_name", "string"},
		{"qtype", "count"}, {"qtype_name", "string"}, {"rcode", "count"}, {"rcode_name", "string"}, {"AA", "bool"}, {"TC", "bool"},
		{"RD", "bool"}, {"RA", "bool"}, {"Z", "count"}, {"answers", "vector[string]"}, {"TTLs", "vector[interval]"}, {"rejected", "bool"},
		{"community_id", "string"}, {"node_id", "string"},
	}),
	stream("ssl", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"version", "string"}, {"cipher", "string"}, {"curve", "string"}, {"server_name", "string"}, {"resumed", "bool"}, {"last_alert", "string"},
		{"next_protocol", "string"}, {"established", "bool"}, {"cert_chain_fuids", "vector[string]"}, {"client_cert_chain_fuids", "vector[string]"},
		{"subject", "string"}, {"issuer", "string"}, {"client_subject", "string"}, {"client_issuer", "string"}, {"validation_status", "string"},
		{"ja3", "string"}, {"ja3s", "string"}, {"ja4", "string"}, {"community_id", "string"}, {"node_id", "string"},
	}),
	stream("http", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"trans_depth", "count"}, {"method", "string"}, {"host", "string"}, {"uri", "string"}, {"referrer", "string"}, {"version", "string"},
		{"user_agent", "string"}, {"origin", "string"}, {"request_body_len", "count"}, {"response_body_len", "count"}, {"status_code", "count"},
		{"status_msg", "string"}, {"info_code", "count"}, {"info_msg", "string"}, {"tags", "set[enum]"}, {"username", "string"},
		{"password", "string"}, {"proxied", "vector[string]"}, {"orig_fuids", "vector[string]"}, {"orig_filenames", "vector[string]"},
		{"orig_mime_types", "vector[string]"}, {"resp_fuids", "vector[string]"}, {"resp_filenames", "vector[string]"}, {"resp_mime_types", "vector[string]"},
		{"community_id", "string"}, {"node_id", "string"},
	}),
	stream("smtp", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"trans_depth", "count"}, {"helo", "string"}, {"mailfrom", "string"}, {"rcptto", "set[string]"}, {"date", "string"}, {"from", "string"},
		{"to", "set[string]"}, {"cc", "set[string]"}, {"reply_to", "string"}, {"msg_id", "string"}, {"in_reply_to", "string"}, {"subject", "string"},
		{"x_originating_ip", "addr"}, {"first_received", "string"}, {"second_received", "string"}, {"last_reply", "string"}, {"path", "vector[string]"},
		{"user_agent", "string"}, {"tls", "bool"}, {"fuids", "vector[string]"}, {"is_webmail", "bool"}, {"community_id", "string"}, {"node_id", "string"},
	}),
	stream("files", []Field{
		{"ts", "time"}, {"fuid", "string"}, {"uid", "string"}, {"source", "string"}, {"depth", "count"}, {"analyzers", "set[string]"},
		{"mime_type", "string"}, {"filename", "string"}, {"duration", "interval"}, {"local_orig", "bool"}, {"is_orig", "bool"},
		{"seen_bytes", "count"}, {"total_bytes", "count"}, {"missing_bytes", "count"}, {"overflow_bytes", "count"}, {"timedout", "bool"},
		{"parent_fuid", "string"}, {"md5", "string"}, {"sha1", "string"}, {"sha256", "string"}, {"hash_complete", "bool"}, {"extracted", "string"},
		{"community_id", "string"}, {"node_id", "string"},
	}),
	stream("radius", []Field{
		{"ts", "time"}, {"uid", "string"}, {"id.orig_h", "addr"}, {"id.orig_p", "port"}, {"id.resp_h", "addr"}, {"id.resp_p", "port"},
		{"proto", "enum"}, {"code", "count"}, {"identifier", "count"}, {"length", "count"},
		{"observation_id", "string"}, {"request_instance_id", "string"}, {"association", "enum"},
		{"attributes", "vector[string]"}, {"origin_node_id", "string"}, {"source_id", "string"}, {"capture_epoch", "string"},
		{"community_id", "string"}, {"node_id", "string"},
	}),
	stream("dhcp", []Field{
		{"ts", "time"},
		{"uid", "string"},
		{"id.orig_h", "addr"},
		{"id.orig_p", "port"},
		{"id.resp_h", "addr"},
		{"id.resp_p", "port"},
		{"proto", "enum"},
		{"op", "count"},
		{"message_type", "count"},
		{"transaction_id", "count"},
		{"hardware_type", "count"},
		{"hardware_address", "string"},
		{"client_identifier", "string"},
		{"client_addr", "addr"},
		{"offered_addr", "addr"},
		{"next_server", "addr"},
		{"relay_addr", "addr"},
		{"server_identifier", "addr"},
		{"requested_addr", "addr"},
		{"hostname", "string"},
		{"domain", "string"},
		{"lease_seconds", "count"},
		{"routers", "vector[addr]"},
		{"dns_servers", "vector[addr]"},
		{"parameter_request_list", "vector[count]"},
		{"association", "enum"},
		{"association_id", "string"},
		{"truncated", "bool"},
		{"community_id", "string"},
		{"node_id", "string"},
		{"capture_scope", "enum"},
		{"partial", "bool"},
	}),
	stream("ntp", []Field{
		{"ts", "time"},
		{"uid", "string"},
		{"id.orig_h", "addr"},
		{"id.orig_p", "port"},
		{"id.resp_h", "addr"},
		{"id.resp_p", "port"},
		{"proto", "enum"},
		{"version", "count"},
		{"mode", "count"},
		{"leap", "count"},
		{"stratum", "count"},
		{"poll", "int"},
		{"precision", "int"},
		{"root_delay_raw", "int"},
		{"root_dispersion_raw", "count"},
		{"reference_id", "string"},
		{"reference_raw", "string"},
		{"origin_raw", "string"},
		{"receive_raw", "string"},
		{"transmit_raw", "string"},
		{"reference_time", "time"},
		{"origin_time", "time"},
		{"receive_time", "time"},
		{"transmit_time", "time"},
		{"association", "enum"},
		{"association_id", "string"},
		{"truncated", "bool"},
		{"community_id", "string"},
		{"node_id", "string"},
		{"capture_scope", "enum"},
		{"partial", "bool"},
	}),
	stream("known_hosts", []Field{
		{"ts", "time"},
		{"uid", "string"},
		{"id.orig_h", "addr"},
		{"id.orig_p", "port"},
		{"id.resp_h", "addr"},
		{"id.resp_p", "port"},
		{"proto", "enum"},
		{"host", "addr"},
		{"evidence", "enum"},
		{"community_id", "string"},
		{"node_id", "string"},
		{"capture_scope", "enum"},
		{"partial", "bool"},
	}),
	stream("known_services", []Field{
		{"ts", "time"},
		{"uid", "string"},
		{"id.orig_h", "addr"},
		{"id.orig_p", "port"},
		{"id.resp_h", "addr"},
		{"id.resp_p", "port"},
		{"proto", "enum"},
		{"host", "addr"},
		{"port", "port"},
		{"transport", "enum"},
		{"service", "string"},
		{"evidence", "enum"},
		{"community_id", "string"},
		{"node_id", "string"},
		{"capture_scope", "enum"},
		{"partial", "bool"},
	}),
}

func stream(name string, fields []Field) Stream {
	return Stream{Name: name, Filename: name + ".log", Fields: fields}
}

// ByName returns the schema for name.
func ByName(name string) (Stream, bool) {
	for _, candidate := range Streams {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return Stream{}, false
}
