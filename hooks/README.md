# Git Hooks for lippycat

This directory contains git hooks used for the lippycat project.

## Pre-commit Hook

The pre-commit hook performs the following checks:

1. **Code Formatting**: Checks that code is formatted with `gofmt`
2. **Secret Detection**: Scans for secrets using `gitleaks`
3. **Go Vet**: Runs `go vet` to catch common errors

### Installation

To install the pre-commit hook, run from the project root:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or use the installation script:

```bash
./install-hooks.sh
```

### Requirements

- `gofmt` (comes with Go)
- `gitleaks` (optional but recommended) - [Install instructions](https://github.com/gitleaks/gitleaks#installing)

If `gitleaks` is not installed, the hook will skip secret detection with a warning.

### Bypassing the Hook

In rare cases where you need to bypass the hook (not recommended):

```bash
git commit --no-verify
```

### Gitleaks Configuration

The `.gitleaks.toml` file configures gitleaks to exclude:
- Test certificates in `test/testcerts/`
- Test keys in `testdata/pcaps/`
- All test files (`*_test.go`)
- Private key patterns in allowed paths

To test gitleaks manually:

```bash
# Scan all files
gitleaks detect

# Scan staged files only
gitleaks protect --staged
```
