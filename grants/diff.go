package grants

import (
	"github.com/juliangruber/go-intersect"
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
	// two indices – the index in current, and the index in new
	hashMap := map[string]int{}

	// because we're modifying slices directly, we need to make local copies to not modify the source slices
	current := make([]v1alpha1.GrantSpec, len(currentGrants))
	new := make([]v1alpha1.GrantSpec, len(newGrants))

	copy(current, currentGrants)
	copy(new, newGrants)

	for i, spec := range current {
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
		record := current[i]
		records := intersection[record.Target]
		records[0] = record
		intersection[record.Target] = records

		// set a zero value for all to remove
		current[i] = v1alpha1.GrantSpec{}
	}

	i = 0
	for {
		if len(current) <= i {
			break
		}
		// if we have a zero object, we unshift it and keep the index as is
		// since the next element will now have the current index.
		if reflect.ValueOf(current[i]).IsZero() {
			copy(current[i:], current[i+1:])
			current = current[:len(current)-1]
			continue
		}

		// otherwise, this element should be kept and we continue iterating
		i++
	}

	//copy(current[i:], current[i+1:])               // Shift a[i+1:] left one index.
	//current[len(current)-1] = v1alpha1.GrantSpec{} // Erase last element (write zero value).
	//current = current[:len(current)-1]             // Truncate slice.

	var output [][2]v1alpha1.GrantSpec
	for _, set := range intersection {
		output = append(output, set)
	}

	return current, output, new
}

func DiffPrivileges(curr, new []string) GrantDiff {
	return GrantDiff{}
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
		// here we want to generate a REVOKE/GRANT list
		oldPerms := intersection[0]
		newPerms := intersection[1]

		// if the new privileges are all privileges, we can do an early return
		if newPerms.Privileges[0] == "*" {
			diff.Grant = append(diff.Grant, newPerms)
			continue
		}

		var permsIntersect []string

		for _, t := range intersect.Hash(oldPerms.Privileges, newPerms.Privileges).([]interface{}) {
			permsIntersect = append(permsIntersect, t.(string))
		}
	}

	return diff
}

func buildTargetIntersection(current, new []v1alpha1.GrantSpec) []v1alpha1.GrantSpec {
	// Check for any grants to change
	// 1. Target intersection
	//var currTargets []string
	//var newTargets []string
	//for _, g := range current {
	//	currTargets = append(currTargets, g.Target)
	//}
	//for _, g := range new {
	//	newTargets = append(newTargets, g.Target)
	//}
	//
	//var targetIntersect []string
	//
	//for _, t := range intersect.Hash(currTargets, newTargets).([]interface{}) {
	//	targetIntersect = append(targetIntersect, t.(string))
	//}
	//
	//return targetIntersect
	return nil
}

func containsString(input []string, search string) bool {
	for _, i := range input {
		if i == search {
			return true
		}
	}

	return false
}
