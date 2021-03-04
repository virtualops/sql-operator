# (My)SQL Operator

**This project is a work in progress**

The SQL Operator manages users and permissions on a MySQL instance.
It aims to make it easy to create database users on a per-service level
with unique credentials and narrow permissions.

## Example usage

```yaml
apiVersion: db.breeze.sh/v1alpha1
kind: User
metadata:
  name: user-sample
spec:
  username: example
  host: '%'
  secretName: example-db-credentials
  grants:
    - target: 'example.*'
      privileges: ['*']
```

This will create a database user with the username `'example'@'%'`,
and execute a `GRANT ALL PRIVILEGES ON example.* TO 'example'@'%'`.
It will generate a random password, and store the connection details for
the user in a secret named `example-db-credentials.`
