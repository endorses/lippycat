package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventSubscriptionRequiresSubscriberRole(t *testing.T) {
	assert.Equal(t, RoleSubscriber, methodRoles["/lippycat.events.v1.EventService/SubscribeEvents"])
}
