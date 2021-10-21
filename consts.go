package chestermodels

// GCFPush means the last updated step was it was received from stack driver to GCF
const GCFPush string = "gcf_push"

// DaemonAck means the daemon acknowledged the incident
const DaemonAck string = "daemon_ack"

// InstanceInsert means the daemon attempted to modify the instance via the sqladmin API. See DataStoreIncident.OperationID for what operation to query.
const InstanceInsert string = "instance_insert"

// ConfigUpdate means the daemon created the instance, and updated the configmap for the related proxysql instance
const ConfigUpdate string = "config_update"

// ProxySQL restart means the proxysql deployment was restarted
const ProxysqlRestart string = "proxysql_restart"

// StatusCheck means it was in the process of waiting to recheck the status of this incident from datastore.
const StatusCheck string = "status_check"

// Closed means that we closed the ticket
const Closed string = "closed"

// Closed means that we closed the ticket and deleted the incident
const Clear string = "clear"

// Fail means that we failed to process the incident in some form
const Fail string = "fail"

// MetaData is the entity type that we look for, for specific instance metadata
const MetaData string = "chester_metadata"

// AddedByChester is the indicator that terraform-chester-provider should ignore it
const AddedByChester string = "Read Replica Added By Chester"

// KMSProjectFormat is used to format the full key name
const KMSProjectFormat string = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s"

// EnvVarProjectID is the project ID environment variable
const EnvVarProjectID string = "PROJECT_ID"

// EnvVarKMSKeyName is the environment variable where chester should look for key names
const EnvVarKMSKeyName string = "KMS_KEY_NAME"

// EnvVarKMSKeyRing is the environment variable where chester should look for the key ring name
const EnvVarKMSKeyRing string = "KMS_KEY_RING"

// EnvVarKMSKeyLocation is the environment variable where chester should look for the key location
const EnvVarKMSKeyLocation string = "KMS_KEY_LOCATION"

// EnvVarKMSKeyVersion is the environment variable where chester should look for the key version
const EnvVarKMSKeyVersion string = "KMS_KEY_VERSION"
