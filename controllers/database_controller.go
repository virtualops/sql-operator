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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dbv1alpha1 "github.com/virtualops/sql-operator/api/v1alpha1"
)

// DatabaseReconciler reconciles a Database object
type DatabaseReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	DB     *sqlx.DB
}

// +kubebuilder:rbac:groups=db.breeze.sh,resources=databases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=db.breeze.sh,resources=databases/status,verbs=get;update;patch

func (r *DatabaseReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("database", req.NamespacedName)
	db := &dbv1alpha1.Database{}

	err := r.Get(ctx, req.NamespacedName, db)

	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}

	if err != nil {
		log.Error(err, "failed to get db")
		return ctrl.Result{}, err
	}

	log.Info("got db", "database", db)

	finalizerName := "db.breeze.sh/finalizer"

	if db.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object.
		if !containsString(db.ObjectMeta.Finalizers, finalizerName) {
			db.ObjectMeta.Finalizers = append(db.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(ctx, db); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(db.ObjectMeta.Finalizers, finalizerName) {
			// our finalizer is present, so lets handle our external dependency

			if _, err := r.DB.Exec(fmt.Sprintf("DROP DATABASE `%s`", db.Spec.Name)); err != nil {
				// if DB deletion fails, fail reconciliation
				return ctrl.Result{}, err
			}

			// If the deletion succeeded, remove the finalizer so deletion can complete
			db.ObjectMeta.Finalizers = removeString(db.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(context.Background(), db); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// If the DB has already been created, we do nothing since the object is immutable
	if !db.Status.CreatedAt.IsZero() {
		log.Info("DB already exists, won't create")
		return ctrl.Result{}, nil
	}

	_, err = r.DB.Exec(fmt.Sprintf("CREATE DATABASE `%s` DEFAULT CHARACTER SET = `%s` DEFAULT COLLATE = `%s`", db.Spec.Name, db.Spec.Encoding, db.Spec.Collation))

	if err != nil {
		return ctrl.Result{}, err
	}

	log.Info("DB created, setting status")

	db.Status.CreatedAt = metav1.NewTime(time.Now())

	err = r.Status().Update(ctx, db)

	return ctrl.Result{}, err
}

func (r *DatabaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dbv1alpha1.Database{}).
		Complete(r)
}

func containsString(input []string, search string) bool {
	for _, i := range input {
		if i == search {
			return true
		}
	}

	return false
}

func removeString(input []string, search string) (output []string) {
	for _, i := range input {
		if i != search {
			output = append(output, i)
		}
	}

	return
}
