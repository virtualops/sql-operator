package grants

import (
	"github.com/stretchr/testify/assert"
	"github.com/virtualops/sql-operator/api/v1alpha1"
	"testing"
)

func TestSegmentByTarget(t *testing.T) {
	currentGrants := []v1alpha1.GrantSpec{
		{
			Target:     "test.remove",
			Privileges: []string{"CREATE", "UPDATE", "SELECT"},
		},
		{
			Target:     "test.change",
			Privileges: []string{"CREATE", "UPDATE", "SELECT"},
		},
	}
	newGrants := []v1alpha1.GrantSpec{
		{
			Target:     "test.change",
			Privileges: []string{"CREATE", "UPDATE", "DELETE"}, // we want -SELECT +DELETE
		},
		{
			Target:     "test.add",
			Privileges: []string{"*"},
		},
	}

	remove, update, add := SegmentByTarget(currentGrants, newGrants)
	assert.Len(t, remove, 1)
	assert.Len(t, add, 1)
	assert.Len(t, update, 1)
	assert.Equal(t, currentGrants[0], remove[0])
	assert.Equal(t, newGrants[1], add[0])
	assert.Equal(t, currentGrants[1], update[0][0])
	assert.Equal(t, newGrants[0], update[0][1])
}
