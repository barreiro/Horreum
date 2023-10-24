# Development

## Build

You will need Java 17 and Maven 3.9 then execute

```bash
mvn clean install
mvn quarkus:dev -pl 'horreum-backend'
```

## Example data

You can preload Horreum with some [example data](https://github.com/Hyperfoil/Horreum/blob/master/infra-legacy/example-configuration.sh) with

```bash
./infra-legacy/example-configuration.sh
```

once Horreum is running.

## OpenAPI

The [OpenAPI](https://www.openapis.org/) for [Horreum](https://github.com/Hyperfoil/Horreum/) will be located in

```bash
./horreum-api/target/generated/openapi.yaml
```

after the build.

The [website](https://horreum.hyperfoil.io/docs/reference/api-reference/) is hosting a copy of the OpenAPI reference.

## Main configuration

The main configuration of Horreum is in the [application.properties](https://github.com/Hyperfoil/Horreum/blob/master/horreum-backend/src/main/resources/application.properties) file.

The database bootstrap script is in the [changeLog.xml](https://github.com/Hyperfoil/Horreum/blob/master/horreum-backend/src/main/resources/db/changeLog.xml)


## Credentials

Horreum is running on [localhost:8080](http://localhost:8080)

| Role | Name | Password |
| ---- | ---- | -------- |
| User | `user` | `secret` |


## Access Keycloak

You can access the Keycloak instance by using the URL provided by the

```bash
curl -k -s http://localhost:8080/api/config/keycloak | jq -r .url
```

command.

The following users are defined

| Role | Name | Password | Realm |
| ---- | ---- | -------- | ----- |
| Admin | `admin` | `secret` | |
| User | `user` | `secret` | `horreum` |

## Troubleshooting development infrastructure

1. Clean cached files and rebuild

```shell
$ mvn clean -p remove-node-cache
$ mvn clean install -DskipTests -DskipITs
```

## Local development with Podman

[Podman 4](https://podman.io/) can be used for the development mode of Horreum.

Install of the podman packages:

``` bash
dnf install -y podman podman-plugins podman-docker
```

In one terminal do
``` bash
podman system service -t 0
```
And then configure `DOCKER_HOST` environment variable to resolve to the podman socket

``` bash
export DOCKER_HOST=unix:///run/user/${UID}/podman/podman.sock
```

and use the standard build commands.

## Using an existing backup

You can use an existing backup of the database (PostgreSQL 13+) by a command like

```bash
mvn  quarkus:dev -pl '!horreum-integration-tests' \
  -Dhorreum.dev-services.postgres.database-backup=/opt/databases/horreum-prod-db/ \
  -Dhorreum.db.secret='M3g45ecr5t!' \
  -Dhorreum.dev-services.keycloak.db-password='prod-password' \
  -Dhorreum.dev-services.keycloak.admin-password='ui-prod-password' \
  -Dquarkus.datasource.username=user \
  -Dquarkus.datasource.password='prod-password' \
  -Dquarkus.liquibase.migration.migrate-at-start=false
```

or by placing a `horreum-backend/.env` file with content like

```
horreum.dev-services.postgres.database-backup=<path/to/db>
horreum.dev-services.keycloak.image=quay.io/keycloak/keycloak:20.0.1
horreum.dev-services.keycloak.db-username=<keycloak-user-name>
horreum.dev-services.keycloak.db-password=<keycloak-user-password>

horreum.dev-services.keycloak.admin-username=<keycloak-admin-name>
horreum.dev-services.keycloak.admin-password=<keycloak-admin-password>

horreum.db.secret=<db-secret>

quarkus.datasource.username=<horreum-user-name>
quarkus.datasource.password=<horreum-user-password>

# Set to `true` to migrate database schema at startup
quarkus.liquibase.migration.migrate-at-start=true
quarkus.liquibase.migration.validate-on-migrate=false

# Need user account with access to public schema
quarkus.datasource.migration.username=<migration-user-name>
quarkus.datasource.migration.password=<migration-user-password>
```