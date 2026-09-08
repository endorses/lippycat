package li

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDestinationDeliveryGenerationBindsIncarnation(t *testing.T) {
	d := Destination{DID: uuid.New(), Address: "mdf.example", Port: 443, CreatedAt: time.Now()}
	generation := DestinationDeliveryGeneration(&d)
	require.NotZero(t, generation)
	copy := d
	require.Equal(t, generation, DestinationDeliveryGeneration(&copy))
	copy.Port++
	require.NotEqual(t, generation, DestinationDeliveryGeneration(&copy))
	copy = d
	copy.CreatedAt = copy.CreatedAt.Add(time.Nanosecond)
	require.NotEqual(t, generation, DestinationDeliveryGeneration(&copy))
}
