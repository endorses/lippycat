//go:build !linux

package securestore

import "errors"

func exchangeNames(int, string, int, string) error {
	return errors.New("securestore: atomic name exchange unsupported")
}
