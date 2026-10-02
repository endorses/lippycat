package li

import "time"

// TaskAuthorizationCutoff returns the task's delivery cutoff. EndTime only
// limits authorization when the ADMF permits implicit deactivation; product
// retention deadlines are independent of this policy.
func TaskAuthorizationCutoff(task *InterceptTask) time.Time {
	if !task.ImplicitDeactivationAllowed {
		return time.Time{}
	}
	return task.EndTime
}
