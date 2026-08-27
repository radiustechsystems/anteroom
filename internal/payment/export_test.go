package payment

import "time"

// shrinkBudgets makes a verifier's timeouts test-sized. Production values stay
// in the constants; only the test binary can reach this.
func (c *CallbackVerifier) shrinkBudgets(verify, settle, path time.Duration) {
	c.verifyBudget, c.settleBudget, c.pathBudget = verify, settle, path
}
