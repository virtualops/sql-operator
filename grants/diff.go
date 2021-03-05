package grants

import (
	"github.com/virtualops/sql-operator/api/v1alpha1"
	"reflect"
)

type GrantDiff struct {
	Revoke []v1alpha1.GrantSpec
	Grant  []v1alpha1.GrantSpec
}

// SegmentByTarget will split the current and new grant specs into three slices
// containing [current - intersection] [intersection] [new - intersection]
func SegmentByTarget(currentGrants, newGrants []v1alpha1.GrantSpec) ([]v1alpha1.GrantSpec, [][2]v1alpha1.GrantSpec, []v1alpha1.GrantSpec) {
	// we create a map from the hash identifier (grant target) to a slice of
	// two indices – the index in remove, and the index in new
	hashMap := map[string]int{}

	// because we're modifying slices directly, we need to make local copies to not modify the source slices
	remove := make([]v1alpha1.GrantSpec, len(currentGrants))
	new := make([]v1alpha1.GrantSpec, len(newGrants))

	copy(remove, currentGrants)
	copy(new, newGrants)

	for i, spec := range remove {
		hashMap[spec.Target] = i
	}

	intersection := map[string][2]v1alpha1.GrantSpec{}


	for target, _ := range hashMap {
		remove := true
		for _, spec := range new {
			if target == spec.Target {
				remove = false
				break
			}
		}

		if remove {
			delete(hashMap, target)
		}
	}

	i := 0
	for {
		if len(new) <= i {
			break
		}
		spec := new[i]

		if _, ok := hashMap[spec.Target]; ok {
			intersection[spec.Target] = [2]v1alpha1.GrantSpec{{}, spec}
			copy(new[i:], new[i+1:])               // Shift a[i+1:] left one index.
			//new[len(new)-1] = v1alpha1.GrantSpec{} // Erase last element (write zero value).
			new = new[:len(new)-1]                 // Truncate slice.
			// we do an early continue to avoid iterating `i` since we shifted the list
			continue
		}

		i++
	}

	for _, i := range hashMap {
		record := remove[i]
		records := intersection[record.Target]
		records[0] = record
		intersection[record.Target] = records

		// set a zero value for all to remove
		remove[i] = v1alpha1.GrantSpec{}
	}

	i = 0
	for {
		if len(remove) <= i {
			break
		}
		// if we have a zero object, we unshift it and keep the index as is
		// since the next element will now have the remove index.
		if reflect.ValueOf(remove[i]).IsZero() {
			copy(remove[i:], remove[i+1:])
			remove = remove[:len(remove)-1]
			continue
		}

		// otherwise, this element should be kept and we continue iterating
		i++
	}

	//copy(remove[i:], remove[i+1:])               // Shift a[i+1:] left one index.
	//remove[len(remove)-1] = v1alpha1.GrantSpec{} // Erase last element (write zero value).
	//remove = remove[:len(remove)-1]             // Truncate slice.

	var output [][2]v1alpha1.GrantSpec
	for _, set := range intersection {
		output = append(output, set)
	}

	return remove, output, new
}

func DiffPrivileges(curr, new v1alpha1.GrantSpec) GrantDiff {
	diff := GrantDiff{}

	if new.Privileges[0] == "*" {
		diff.Grant = append(diff.Grant, new)

		return diff
	}

	diff.Revoke  = []v1alpha1.GrantSpec{{
		Target: curr.Target,
	}}

	for _, privilege := range curr.Privileges {
		revoke := true
		for _, retainedPrivilege := range new.Privileges {
			if privilege == retainedPrivilege {
				revoke = false
				break
			}
		}

		if revoke {
			diff.Revoke[0].Privileges = append(diff.Revoke[0].Privileges, privilege)
		}
	}

	diff.Grant = []v1alpha1.GrantSpec{{
		Target: curr.Target,
	}}

	for _, privilege := range new.Privileges {
		grant := true
		for _, oldPrivilege := range curr.Privileges {
			if privilege == oldPrivilege {
				grant = false
				break
			}
		}

		if grant {
			diff.Grant[0].Privileges = append(diff.Grant[0].Privileges, privilege)
		}
	}

	return diff
}

func GenerateExecutionPlan(current, new []v1alpha1.GrantSpec) GrantDiff {
	diff := GrantDiff{}

	// 1. Intersect the targets
	remove, update, add := SegmentByTarget(current, new)
	// 2. For each current that is not in the intersect (removed), revoke all on the target
	diff.Revoke = remove
	// 3. For each new that is not in the intersect (added), grant specified permissions on the target
	diff.Grant = add
	// 4. Loop through the target intersection and generate a permissions diff per target
	for _, intersection := range update {
		innerDiff := DiffPrivileges(intersection[0], intersection[1])

		if len(innerDiff.Grant[0].Privileges) > 0 {
			diff.Grant = append(diff.Grant, innerDiff.Grant[0])
		}

		if len(innerDiff.Revoke[0].Privileges) > 0 {
			diff.Revoke = append(diff.Revoke, innerDiff.Revoke[0])
		}
	}

	return diff
}
