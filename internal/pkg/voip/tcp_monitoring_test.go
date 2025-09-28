package voip

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSipStreamFactoryGoroutineMonitoring(t *testing.T) {
	t.Run("Factory initialization", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		factory := NewSipStreamFactory(ctx)
		sipFactory, ok := factory.(*sipStreamFactory)
		assert.True(t, ok, "Factory should be of correct type")

		// Initially no active goroutines
		assert.Equal(t, int64(0), sipFactory.GetActiveGoroutines())
		assert.Equal(t, int64(DefaultGoroutineLimit), sipFactory.GetMaxGoroutines())

		// Test monitoring methods exist and return valid values
		assert.True(t, sipFactory.GetMaxGoroutines() > 0)
		assert.True(t, sipFactory.GetActiveGoroutines() >= 0)

		factory.(*sipStreamFactory).Close()
	})

	t.Run("Goroutine limit configuration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		factory := NewSipStreamFactory(ctx)
		sipFactory, ok := factory.(*sipStreamFactory)
		assert.True(t, ok, "Factory should be of correct type")

		// Test that we can set different limits
		sipFactory.config.MaxGoroutines = 500
		assert.Equal(t, int64(500), sipFactory.GetMaxGoroutines())

		sipFactory.config.MaxGoroutines = 100
		assert.Equal(t, int64(100), sipFactory.GetMaxGoroutines())

		factory.(*sipStreamFactory).Close()
	})
}
