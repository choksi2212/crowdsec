package cookie

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPartitionedRendersAttributeAndPromotesSecure covers the CHIPS cookie
// attribute: a Partitioned cookie must render the Partitioned attribute and
// be promoted to Secure (CHIPS requires it), whether or not the caller set
// Secure explicitly.
func TestPartitionedRendersAttributeAndPromotesSecure(t *testing.T) {
	t.Run("partitioned adds the attribute and promotes Secure", func(t *testing.T) {
		rendered := Cookie("t").Value("v").Partitioned().String()
		require.Contains(t, rendered, "Partitioned", "the Partitioned attribute must be rendered")
		assert.Contains(t, rendered, "Secure", "Partitioned must imply Secure")
		assert.Contains(t, rendered, "SameSite=Lax", "Partitioned alone must not change SameSite")
	})

	t.Run("plain cookie stays unpartitioned and insecure", func(t *testing.T) {
		rendered := Cookie("t").Value("v").String()
		assert.NotContains(t, rendered, "Partitioned", "a plain cookie must not claim Partitioned")
		assert.NotContains(t, rendered, "Secure", "a plain cookie must not claim Secure")
	})

	t.Run("partitioned keeps an explicit Secure", func(t *testing.T) {
		rendered := Cookie("t").Value("v").Secure().Partitioned().String()
		require.Contains(t, rendered, "Partitioned")
		assert.Equal(t, 1, strings.Count(rendered, "Secure"), "Secure must appear exactly once")
	})
}
