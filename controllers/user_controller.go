/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/juliangruber/go-intersect"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dbv1alpha1 "github.com/virtualops/sql-operator/api/v1alpha1"
)

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	DB     *sqlx.DB
}

// +kubebuilder:rbac:groups=db.breeze.sh,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=db.breeze.sh,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=create

func (r *UserReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("user", req.NamespacedName)

	user := &dbv1alpha1.User{}

	err := r.Get(ctx, req.NamespacedName, user)

	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}

	if err != nil {
		log.Error(err, "failed to get user")
		return ctrl.Result{}, err
	}

	log.Info("got user", "user", user)

	finalizerName := "db.breeze.sh/finalizer"

	if user.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object.
		if !containsString(user.ObjectMeta.Finalizers, finalizerName) {
			user.ObjectMeta.Finalizers = append(user.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(ctx, user); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(user.ObjectMeta.Finalizers, finalizerName) {
			// our finalizer is present, so lets handle our external dependency

			if _, err := r.DB.Exec(fmt.Sprintf("DROP USER `%s`", user.Spec.Username)); err != nil {
				// if DB deletion fails, fail reconciliation
				return ctrl.Result{}, err
			}

			// If the deletion succeeded, remove the finalizer so deletion can complete
			user.ObjectMeta.Finalizers = removeString(user.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(context.Background(), user); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// If we don't have a creation timestamp, we'll create the user
	if user.Status.CreatedAt.IsZero() {
		password := rand.String(16)
		_, err := r.DB.Exec(fmt.Sprintf("CREATE USER '%s'@'%s' IDENTIFIED BY '%s'", user.Spec.Username, user.Spec.Host, password))

		if err != nil {
			return ctrl.Result{}, err
		}

		log.WithValues("secret_name", user.Spec.SecretName)
		// We'll store the credentials in a secret
		err = r.Create(ctx, &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      user.Spec.SecretName,
				Namespace: user.Namespace,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: user.APIVersion,
					Kind:       user.Kind,
					Name:       user.Name,
					UID:        user.UID,
				}},
			},
			StringData: map[string]string{
				"DB_USERNAME": user.Spec.Username,
				"DB_PASSWORD": password,
			},
		})

		if err != nil {
			return ctrl.Result{}, err
		}

		user.Status.CreatedAt = metav1.NewTime(time.Now())

		err = r.Status().Update(ctx, user)

		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Check for any grants to change
	// 1. Target intersection
	var currTargets []string
	var newTargets []string
	for _, g := range user.Status.CurrentGrants {
		currTargets = append(currTargets, g.Target)
	}
	for _, g := range user.Spec.Grants {
		newTargets = append(newTargets, g.Target)
	}

	var targetIntersect []string

	for _, t := range intersect.Hash(currTargets, newTargets).([]interface{}) {
		targetIntersect = append(targetIntersect, t.(string))
	}

	for _, g := range user.Status.CurrentGrants {
		// We will remove all currently applied grants that do not intersect with new grants
		if containsString(targetIntersect, g.Target) {
			continue
		}

		log.WithValues("target", g.Target).Info("revoking grants")
		_, err := r.DB.Exec(fmt.Sprintf("REVOKE ALL FROM '%s'@'%s' ON %s", user.Spec.Username, user.Spec.Host, g.Target))

		if err != nil {
			return ctrl.Result{}, nil
		}

		user.Status.CurrentGrants = removeGrantFromListByTarget(user.Status.CurrentGrants, g)

		err = r.Status().Update(ctx, user)

		if err != nil {
			return ctrl.Result{}, nil
		}
	}

	for _, g := range user.Spec.Grants {
		// If a new grant target is not in the intersection, it should be added
		if containsString(targetIntersect, g.Target) {
			continue
		}

		if len(g.Privileges) == 0 {
			continue
		}

		privilegeString := getPrivilegeExpression(g)

		log.WithValues("target", g.Target, "privileges", privilegeString).Info("granting new permissions")
		_, err := r.DB.Exec(fmt.Sprintf("GRANT %s ON %s TO '%s'@'%s'", privilegeString, g.Target, user.Spec.Username, user.Spec.Host))

		if err != nil {
			return ctrl.Result{}, err
		}

		user.Status.CurrentGrants = append(user.Status.CurrentGrants, g)

		err = r.Status().Update(ctx, user)

		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func removeGrantFromListByTarget(list []dbv1alpha1.GrantSpec, g dbv1alpha1.GrantSpec) (output []dbv1alpha1.GrantSpec) {
	for _, grant := range list {
		if grant.Target != g.Target {
			output = append(output, grant)
		}
	}

	return
}

func getPrivilegeExpression(g dbv1alpha1.GrantSpec) string {
	privilegeString := ""
	if len(g.Privileges) == 1 && g.Privileges[0] == "*" {
		privilegeString = "ALL PRIVILEGES"
	} else {
		privilegeString = strings.Join(g.Privileges, ", ")
	}
	return privilegeString
}

func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dbv1alpha1.User{}).
		Complete(r)
}
