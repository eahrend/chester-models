# chestermodels

Package chestermodels contains common structs and methods
across the chester apps.

## Constants

AddedByChester is the indicator that terraform-chester-provider should ignore it

```golang
const AddedByChester string = "Read Replica Added By Chester"
```

Closed means that we closed the ticket and deleted the incident

```golang
const Clear string = "clear"
```

Closed means that we closed the ticket

```golang
const Closed string = "closed"
```

ConfigUpdate means the daemon created the instance, and updated the configmap for the related proxysql instance

```golang
const ConfigUpdate string = "config_update"
```

DaemonAck means the daemon acknowledged the incident

```golang
const DaemonAck string = "daemon_ack"
```

EnvVarKMSKeyLocation is the environment variable where chester should look for the key location

```golang
const EnvVarKMSKeyLocation string = "KMS_KEY_LOCATION"
```

EnvVarKMSKeyName is the environment variable where chester should look for key names

```golang
const EnvVarKMSKeyName string = "KMS_KEY_NAME"
```

EnvVarKMSKeyRing is the environment variable where chester should look for the key ring name

```golang
const EnvVarKMSKeyRing string = "KMS_KEY_RING"
```

EnvVarKMSKeyVersion is the environment variable where chester should look for the key version

```golang
const EnvVarKMSKeyVersion string = "KMS_KEY_VERSION"
```

EnvVarProjectID is the project ID environment variable

```golang
const EnvVarProjectID string = "PROJECT_ID"
```

Fail means that we failed to process the incident in some form

```golang
const Fail string = "fail"
```

GCFPush means the last updated step was it was received from stack driver to GCF

```golang
const GCFPush string = "gcf_push"
```

InstanceInsert means the daemon attempted to modify the instance via the sqladmin API. See DataStoreIncident.OperationID for what operation to query.

```golang
const InstanceInsert string = "instance_insert"
```

KMSProjectFormat is used to format the full key name

```golang
const KMSProjectFormat string = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s"
```

MetaData is the entity type that we look for, for specific instance metadata

```golang
const MetaData string = "chester_metadata"
```

ProxySQL restart means the proxysql deployment was restarted

```golang
const ProxysqlRestart string = "proxysql_restart"
```

StatusCheck means it was in the process of waiting to recheck the status of this incident from datastore.

```golang
const StatusCheck string = "status_check"
```

## Types

### type [AddDatabaseRequest](/models.go#L632)

`type AddDatabaseRequest struct { ... }`

AddDatabaseRequest represents an incoming request from a client
(like terraform) to the API to create a new instance group in datastore.
This won't create a deployment of proxysql, so make sure that at least is
done first.

### type [AddDatabaseRequestDatabaseInformation](/models.go#L665)

`type AddDatabaseRequestDatabaseInformation struct { ... }`

AddDatabaseRequestDatabaseInformation contains the bare minimum information
required to add an instance to an instance group. The rest is inferred from
the other structs.

### type [AddDatabaseResponse](/models.go#L672)

`type AddDatabaseResponse struct { ... }`

AddDatabaseResponse is the response from the API to the client after
an instance group is created.

### type [ChesterMetaData](/models.go#L768)

`type ChesterMetaData struct { ... }`

ChesterMetaData is the struct that holds metadata about a specific instance's
data, currently it's just a map[string]string{} so I have to modify it to use this

### type [DataStoreCondition](/models.go#L104)

`type DataStoreCondition struct { ... }`

DataStoreCondition contains policy data about the incident

### type [DataStoreDocumentation](/models.go#L79)

`type DataStoreDocumentation struct { ... }`

DataStoreDocumentation is metadata about the alert stored in the documentation attribute

### type [DataStoreIncident](/models.go#L37)

`type DataStoreIncident struct { ... }`

DataStoreIncident is the incident structure inside of datastore, created from
stackdriver alerting.

### type [DatabaseHost](/models.go#L272)

`type DatabaseHost struct { ... }`

DatabaseHost is used somewhere? Not sure, need to find this

### type [IncidentRequest](/models.go#L24)

`type IncidentRequest struct { ... }`

IncidentRequest stores high level data about an incident triggered from GCP monitoring

### type [InicidentMetaData](/models.go#L89)

`type InicidentMetaData struct { ... }`

InicidentMetaData contains metadata about instances in the incident.
Stored in DataStoreDocumentation.Content as a json string

### type [InstanceData](/models.go#L742)

`type InstanceData struct { ... }`

InstanceData is a simplified struct for the proxysql config, used primarly
by client APIs so they don't need to know the entire configuration.

### type [InstanceMetaData](/models.go#L30)

`type InstanceMetaData struct { ... }`

InstanceMetaData - Need to double check where this actually is used,

### type [ModifyDatabaseRequest](/models.go#L711)

`type ModifyDatabaseRequest struct { ... }`

ModifyDatabaseRequest is the request sent from a client to the API
in order to modify an instance, i.e. if you want to add another permanent
read replica.

### type [ModifyUserRequest](/models.go#L731)

`type ModifyUserRequest struct { ... }`

ModifyUserRequest isn't used, but the endpoints exist for it.
TODO: Deprecate modify user requests

### type [ProxySQLKMSOption](/models.go#L368)

`type ProxySQLKMSOption func(*ProxySqlConfig)`

ProxySQLKMSOption are options specific to the kms configuration
since we can set and get these as needed

### type [ProxySqlConfig](/models.go#L116)

`type ProxySqlConfig struct { ... }`

ProxySqlConfig is the datastore/libconfig struct that configures a proxysql instance.
Contains a combination of actual proxysql configuration stuff, but also some extra
configuration options. Gonna be real with you chief, a lot of these I don't know what they
do. I'm using a lot of defaults here, but if they need to be tweaked we can check
proxysql documentation.

#### func (*ProxySqlConfig) [AddReadReplica](/models.go#L622)

`func (psql *ProxySqlConfig) AddReadReplica(readReplica ProxySqlMySqlServer)`

AddReadReplica adds a read replica in the form of a ProxySqlMySqlServer
to the proxysql config

#### func (*ProxySqlConfig) [DecryptPasswords](/models.go#L341)

`func (psql *ProxySqlConfig) DecryptPasswords(client *kms.KeyManagementClient) error`

DecryptPasswords gets the kms key and allows us to decrypt the passwords encrypted
by psql.EncryptPasswords and get the plaintext versions of them so we can add them
to the kubernetes secret

#### func (*ProxySqlConfig) [EncryptPasswords](/models.go#L305)

`func (psql *ProxySqlConfig) EncryptPasswords(client *kms.KeyManagementClient) error`

EncryptPasswords goes through the users and encrypts all of the passwords using
a public key on KMS.

#### func (*ProxySqlConfig) [GetFullKMSName](/models.go#L284)

`func (psql *ProxySqlConfig) GetFullKMSName() (string, error)`

GetFullKMSName returns the full kms name to use by a kms client

#### func (*ProxySqlConfig) [InitDefaults](/models.go#L440)

`func (psql *ProxySqlConfig) InitDefaults()`

InitDefaults creates a bunch of default stuff to make it easier
to modify rather than building this all out of the gate.

#### func (*ProxySqlConfig) [MarshallJSON](/models.go#L548)

`func (psql *ProxySqlConfig) MarshallJSON() []byte`

#### func (*ProxySqlConfig) [ToLibConfig](/models.go#L559)

`func (psql *ProxySqlConfig) ToLibConfig() ([]byte, error)`

ToLibConfig converts the ProxySqlConfig struct to a libconfig
byte slice.
TODO: GCP uses 1:1 for ssl and replica, SSL won't work

```go
with proxysql. I have an issue open with them to fix
this, or I'll do it myself
[https://github.com/sysown/proxysql/issues/3331](https://github.com/sysown/proxysql/issues/3331)
```

#### func (*ProxySqlConfig) [WithKMSOpts](/models.go#L406)

`func (psql *ProxySqlConfig) WithKMSOpts(opts ...ProxySQLKMSOption)`

WithKMSOpts allows us to set specific kms configurations

#### func (*ProxySqlConfig) [WithKMSOptsFromEnv](/models.go#L413)

`func (psql *ProxySqlConfig) WithKMSOptsFromEnv() error`

WithKMSOptsFromEnv takes the kms configuration from the environment and applies them

### type [ProxySqlConfigAdminVariables](/models.go#L159)

`type ProxySqlConfigAdminVariables struct { ... }`

ProxySqlConfigAdminVariables contains data about how proxysql itself is configured

### type [ProxySqlConfigMysqlVariables](/models.go#L212)

`type ProxySqlConfigMysqlVariables struct { ... }`

ProxySqlConfigMysqlVariables are the variables that get loaded into global_variables that are prefixed with mysql-

### type [ProxySqlMySqlQueryRule](/models.go#L170)

`type ProxySqlMySqlQueryRule struct { ... }`

ProxySqlMySqlQueryRule is a representation of a proxysql query rule

### type [ProxySqlMySqlServer](/models.go#L197)

`type ProxySqlMySqlServer struct { ... }`

ProxySqlMySqlServer contains data about the sql server

### type [ProxySqlMySqlUser](/models.go#L187)

`type ProxySqlMySqlUser struct { ... }`

### type [RemoveDatabaseRequest](/models.go#L698)

`type RemoveDatabaseRequest struct { ... }`

RemoveDatabaseRequest is sent from a client to the API
when an instance group no longer should be managed by chester

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
