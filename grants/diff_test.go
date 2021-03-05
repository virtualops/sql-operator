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

func TestGenerateExecutionPlan(t *testing.T) {
	currentGrants := []v1alpha1.GrantSpec{
		{
			Target:     "test.remove",
			Privileges: []string{"CREATE", "UPDATE", "SELECT"},
		},
		{
			Target:     "test.change",
			Privileges: []string{"CREATE", "UPDATE", "SELECT"},
		},
		{
			Target:     "test.unchanged",
			Privileges: []string{"SELECT"},
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
		{
			Target:     "test.unchanged",
			Privileges: []string{"SELECT"},
		},
	}

	diff := GenerateExecutionPlan(currentGrants, newGrants)
	assert.Len(t, diff.Grant, 2) // 1 grant to add test.add, one to GRANT DELETE
	assert.Len(t, diff.Revoke, 2) // 1 revoke to remove test.remove, one to REVOKE SELECT

	assert.Equal(t, newGrants[1], diff.Grant[0])
	assert.Equal(t, currentGrants[0], diff.Revoke[0])
	assert.Equal(t, v1alpha1.GrantSpec{
		Target: "test.change",
		Privileges: []string{"DELETE"},
	}, diff.Grant[1])
	assert.Equal(t, v1alpha1.GrantSpec{
		Target: "test.change",
		Privileges: []string{"SELECT"},
	}, diff.Revoke[1])
}

func TestGenerateExecutionPlanWithoutCurrentGrants(t *testing.T) {
	newGrants := []v1alpha1.GrantSpec{
		{
			Target:     "test.change",
			Privileges: []string{"CREATE", "UPDATE", "DELETE"},
		},
		{
			Target:     "test.add",
			Privileges: []string{"*"},
		},
	}

	diff := GenerateExecutionPlan(nil, newGrants)
	assert.Len(t, diff.Grant, 2) // 1 grant to add test.add, one to GRANT DELETE
	assert.Len(t, diff.Revoke, 0) // 1 revoke to remove test.remove, one to REVOKE SELECT

	assert.Equal(t, diff.Grant, newGrants)
}
