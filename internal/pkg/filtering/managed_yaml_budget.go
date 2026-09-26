package filtering

// managedYAMLSyntaxBudget bounds syntax work before yaml.v3 materializes Nodes.
// It is a lexical resource preflight, not a YAML validator: yaml.v3 still owns
// grammar and scalar decoding. Quoted, plain and block scalar text and comments
// do not count as collections. Field validation happens on the bounded tree.
// Admission charges 4*source bytes, 320 bytes per scalar/flow collection/sequence
// item, and 80 bytes per mapping separator against the 256 MiB reservation. The
// scalar charge includes implicit block-map Nodes; separator charges cover map
// content arrays and typed fields without charging another complete Node per
// field. Collection/scalar caps remain independent maxima, not an entitlement
// to consume them simultaneously. Allocation regression tests exercise dense
// syntax, schema-rich candidates, and the maximum ordinary filter count.
func managedYAMLSyntaxBudget(data []byte) error {
	units, flow, lineStart, lineIndent, inlineSequences := 0, 0, 0, 0, 0
	mappings := 0
	valueIndent, lastScalarColumn, plainIndent := 0, 0, 0
	plainContinues := false
	newLine := true
	indents := []int{0}
	space := func(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
	separator := func(i int) bool {
		return i >= len(data) || space(data[i]) || flow > 0 && (data[i] == '[' || data[i] == ']' || data[i] == '{' || data[i] == '}' || data[i] == ',')
	}
	for i := 0; i < len(data); {
		if space(data[i]) {
			if data[i] == '\n' {
				lineStart, newLine, inlineSequences = i+1, true, 0
			}
			i++
			continue
		}
		if data[i] == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		if newLine {
			lineIndent = i - lineStart
			// Continuation lines belong to the previous plain scalar. A quote
			// here is literal text, not an opening quote that could hide a
			// subsequent outdented collection from resource accounting.
			if flow == 0 && plainContinues && lineIndent > plainIndent {
				for i < len(data) && data[i] != '\n' {
					i++
				}
				continue
			}
			plainContinues = false
			valueIndent = lineIndent
			if flow == 0 {
				for len(indents) > 1 && lineIndent < indents[len(indents)-1] {
					indents = indents[:len(indents)-1]
				}
				if lineIndent > indents[len(indents)-1] {
					indents = append(indents, lineIndent)
				}
			}
			newLine = false
		}
		if len(indents)+flow+inlineSequences > maxManagedDepth {
			return managedError("syntax depth limit exceeded")
		}
		start := i
		if i == lineStart && i+3 <= len(data) && (string(data[i:i+3]) == "---" || string(data[i:i+3]) == "...") && separator(i+3) {
			plainContinues = false
			i += 3
			continue
		}
		switch data[i] {
		case '[', '{':
			plainContinues = false
			flow++
			units++
			i++
		case ']', '}':
			if flow > 0 {
				flow--
			}
			i++
		case ',':
			i++
		case ':':
			// Every block mapping has at least one separator. Charging all
			// separators bounds mapping Nodes without parsing indentation keys.
			mappings++
			valueIndent, plainContinues = lastScalarColumn, false
			i++
		case '!':
			// Tags precede their value rather than turning it into plain
			// text. Node validation rejects unsupported tags afterward.
			units++
			i++
			if i < len(data) && data[i] == '<' {
				for i < len(data) && data[i] != '>' {
					i++
				}
				if i < len(data) {
					i++
				}
			} else {
				for i < len(data) && !separator(i) {
					i++
				}
			}
		case '&', '*':
			return managedError("YAML anchors and aliases are not supported")
		case '\'', '"':
			lastScalarColumn, plainContinues = i-lineStart, false
			quote := data[i]
			units++
			i++
			for i < len(data) {
				if quote == '"' && data[i] == '\\' {
					i++
					if i < len(data) {
						i++
					}
					continue
				}
				if data[i] == quote {
					i++
					if quote == '\'' && i < len(data) && data[i] == '\'' {
						i++
						continue
					}
					break
				}
				i++
			}
		case '|', '>':
			plainContinues = false
			units++
			i = managedBlockScalarEnd(data, i, valueIndent)
		default:
			if data[i] == '?' && separator(i+1) {
				units++
				plainContinues = false
				i++
				break
			}
			if data[i] == '-' && separator(i+1) {
				units++
				inlineSequences++
				valueIndent, plainContinues = i-lineStart, false
				i++
				break
			}
			// A plain scalar may contain quotes, braces and spaces. Quotes
			// within it never hide structure belonging to another scalar.
			units++
			lastScalarColumn = i - lineStart
			for i < len(data) {
				b := data[i]
				if b == '\n' || b == '\r' || b == ':' && separator(i+1) ||
					flow > 0 && (b == '[' || b == ']' || b == '{' || b == '}' || b == ',') ||
					b == '#' && i > start && space(data[i-1]) {
					break
				}
				i++
			}
			if flow == 0 {
				plainContinues, plainIndent = true, valueIndent
			}
		}
		if units > maxManagedSyntaxUnits || 4*len(data)+units*managedSyntaxBytes+mappings*managedMappingBytes > maxManagedDecodeBytes || len(indents)+flow+inlineSequences > maxManagedDepth {
			return managedError("syntax allocation or depth limit exceeded")
		}
		// Quoted and block scalars can span lines. Their content does not
		// establish YAML nesting levels, but the next real token must see
		// its actual source column.
		for j := start; j < i; j++ {
			if data[j] == '\n' {
				lineStart, newLine, inlineSequences = j+1, true, 0
			}
		}
		if i > lineStart {
			newLine = false
		}
	}
	return nil
}

func managedBlockScalarEnd(data []byte, start, parentIndent int) int {
	i, requiredIndent := start+1, 0
	// Optional chomping and indentation indicators occur before comments.
	for i < len(data) && data[i] != '\n' {
		if data[i] == '#' || data[i] == ' ' || data[i] == '\t' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			break
		}
		if data[i] >= '1' && data[i] <= '9' {
			requiredIndent = parentIndent + int(data[i]-'0')
		}
		i++
	}
	if i < len(data) {
		i++
	}
	for i < len(data) {
		line := i
		for i < len(data) && data[i] == ' ' {
			i++
		}
		if i == len(data) {
			return i
		}
		if data[i] == '\n' || data[i] == '\r' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				i++
			}
			continue
		}
		indent := i - line
		if indent <= parentIndent || requiredIndent != 0 && indent < requiredIndent {
			return line
		}
		if requiredIndent == 0 {
			requiredIndent = indent
		}
		for i < len(data) && data[i] != '\n' {
			i++
		}
		if i < len(data) {
			i++
		}
	}
	return i
}
