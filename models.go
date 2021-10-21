// Package chestermodels contains common structs and methods
// across the chester apps.
package chestermodels

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"text/template"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// IncidentRequest stores high level data about an incident triggered from GCP monitoring
type IncidentRequest struct {
	// Incident refers to the DataStoreIncident object
	Incident DataStoreIncident `json:"incident"`
}

// InstanceMetaData - Need to double check where this actually is used,
type InstanceMetaData struct {
	// InstanceMetaData - Need to double check where this is actually used
	InstanceMetaData string `json:"instance_metadata" datastore:"instance_metadata"`
}

// DataStoreIncident is the incident structure inside of datastore, created from
// stackdriver alerting.
type DataStoreIncident struct {
	// IncidentID is the incident ID created from the stackdriver alert.
	IncidentID string `json:"incident_id"`
	// PolicyName is the name of the alert that triggered this incident.
	PolicyName string `json:"policy_name"`
	// State is the current state of the incident, i.e. OPEN/CLOSED/SILENCED
	State string `json:"state"`
	// StartedAt is the time in unix epoch when the alert was fired.
	StartedAt int64 `json:"started_at"`
	// ClosedTimestamp is the datetime string when the alert was closed
	ClosedTimestamp string `json:"closed_timestamp"`
	// Condition contains data about how this alert was fired, not used for chester
	// but useful to have some extra information about this.
	Condition DataStoreCondition `json:"condition"`
	// SqlMasterInstance pulls multiple duties, it's the name of the master instance
	// and the instance group.
	SqlMasterInstance string `json:"sql_master_instance"`
	// ReplicaBaseName is the base name of the replica used by chester-daemon to
	// create replicas.
	ReplicaBaseName string `json:"replica_basename"`
	// Documentation refers to the documentation field in datastore, we're hijacking it
	// to leverage some metadata about how to handle these requests.
	Documentation DataStoreDocumentation `json:"documentation"`
	// InProgress is somewhat the same of State, but it comes from chester-daemon
	InProgress bool `json:"in_progress,omitempty"`
	// Action refers to whether we add or remove read replicas.
	Action string `json:"action"`
	// LastProcess will give us the last thing the daemon attempted to do before it was killed.
	LastProcess string `json:"last_process"`
	// OperationID is the way we can query an operation that was done against the sql admin API
	OperationID string `json:"operation_id"`
	// LastUpdated shows us when the incident was last updated, I'll add the RFC to this comment later
	LastUpdated string `json:"last_updated"`
	// LastUpdatedBy shows us what actor last updated this request.
	LastUpdatedBy string `json:"last_updated_by"`
	// LastIPAddress is the last read replica IP address added
	LastIPAddress string `json:"last_ip_address"`
	// LastReadReplica is the name of the last read replica added for this incident
	LastReadReplicaName string `json:"last_read_replica_name"`
}

// DataStoreDocumentation is metadata about the alert stored in the documentation attribute
type DataStoreDocumentation struct {
	// Content contains the data we care about, as a JSON string
	Content string `json:"content"`
	// MimeType is the type of media inside of the content, here mostly
	// just for completion's sake.
	MimeType string `json:"mime_type"`
}

// InicidentMetaData contains metadata about instances in the incident.
// Stored in DataStoreDocumentation.Content as a json string
type InicidentMetaData struct {
	// ReplicaBaseName contains the base name of the replica, usually
	// something like databasename-replica-
	ReplicaBaseName string `json:"replica_basename"`
	// SqlMasterInstance refers to both the writer instance and the
	// instance group name
	SqlMasterInstance string `json:"sql_master_instance"`
	// Action refers to whether we add read replicas or remove read replicas
	Action string `json:"action"`
	// InstanceGroup is usually the same as SqlMasterInstance, but
	// it can be different if there is a need for it.
	InstanceGroup string `json:"instance_group"`
}

// DataStoreCondition contains policy data about the incident
type DataStoreCondition struct {
	// IncidentID refers to the incident created by stackdriver alerting
	IncidentID string `json:"incident_id"`
	// PolicyName refers to the name of the alert that was triggered
	PolicyName string `json:"policy_name"`
}

// ProxySqlConfig is the datastore/libconfig struct that configures a proxysql instance.
// Contains a combination of actual proxysql configuration stuff, but also some extra
// configuration options. Gonna be real with you chief, a lot of these I don't know what they
// do. I'm using a lot of defaults here, but if they need to be tweaked we can check
// proxysql documentation.
type ProxySqlConfig struct {
	// DataDir defines the path of the ProxySQL datadir, where the database file
	// the logs and other files are stored.
	DataDir string `libconfig:"datadir" json:"datadir"`
	// AdminVariables contains the data about proxysql administration
	AdminVariables ProxySqlConfigAdminVariables `libconfig:"admin_variables" json:"admin_variables"`
	// MysqlVariables contains data about the proxysql configuration
	MysqlVariables ProxySqlConfigMysqlVariables `libconfig:"mysql_variables" json:"mysql_variables"`
	// MySqlServers is a list of ProxySqlMySqlServer structs, which contains
	// data about the sql servers that proxysql is proxying
	MySqlServers []ProxySqlMySqlServer `libconfig:"mysql_servers" json:"mysql_servers"`
	// MySqlUsers is a list of ProxySqlMySqlUser, which contains data about how proxysql
	// connects to the backend sql servers and how the clients connect to proxysql
	MySqlUsers []ProxySqlMySqlUser `libconfig:"mysql_users" json:"mysql_users"`
	// MySqlQueryRules is a list of ProxySqlMySqlQueryRule, which contain the rules on how
	// queries get sent to which host group.
	MySqlQueryRules []ProxySqlMySqlQueryRule `libconfig:"mysql_query_rules" json:"mysql_query_rules"`
	// ReadHostGroup refers to the host group number for read
	// replicas.
	ReadHostGroup int `json:"read_hostgroup"`
	// WriteHostGroup refers to the host group that contains the master instance.
	WriteHostGroup int `json:"write_hostgroup"`
	// UseSSL is currently not used, but potentially used in the future.
	UseSSL int `json:"use_ssl"`
	// KeyData is currently not used, but potentially used in the future.
	KeyData string `json:"key,omitempty"`
	// CertData is currently not used, but potentially used in the future.
	CertData string `json:"cert,omitempty"`
	// CAData is currently not used, but potentially used in the future.
	CAData string `json:"ca_data,omitempty"`
	// KMSProject indicates what project the KMS key exists in
	KMSProject string `json:"kms_project"`
	// KMSLocation indicates where the key is located
	KMSLocation string `json:"kms_location"`
	// KMSKeyRing indicates what the name of the key ring is
	KMSKeyRing string `json:"kms_key_ring"`
	// KMSKeyName indicates the name of the key
	KMSKeyName string `json:"kms_key_name"`
	// KMSKeyVersion indicates the version of the key
	KMSKeyVersion string `json:"kms_key_version"`
}

// ProxySqlConfigAdminVariables contains data about how proxysql itself is configured
type ProxySqlConfigAdminVariables struct {
	// AdminCredentials are the login creds for the proxysql admin
	AdminCredentials string `libconfig:"admin_credentials" json:"admin_credentials"`
	// MysqlIFaces are the network interfaces for proxysql
	MysqlIFaces string `libconfig:"mysql_ifaces" json:"mysql_ifaces"`
	// RefreshInterval The refresh interval (in microseconds) for updates to the query
	// rules statistics and commands counters statistics
	RefreshInterval int64 `libconfig:"refresh_interval" json:"refresh_interval"`
}

// ProxySqlMySqlQueryRule is a representation of a proxysql query rule
type ProxySqlMySqlQueryRule struct {
	// RuleID is the main identifier of a rule
	RuleID int `libconfig:"rule_id" json:"rule_id"`
	// Username filters on username, if it doesn't match the query rule won't be applied
	Username string `libconfig:"username" json:"username"`
	// Active is a int(bool) that says whether or not this should be used or not
	Active int `libconfig:"active" json:"active"`
	// MatchDigest does a regex match against incoming queries
	MatchDigest string `libconfig:"match_digest" json:"match_digest"`
	// DestinationHostgroup will send matching queries to the specified host group
	DestinationHostgroup int `libconfig:"destination_hostgroup" json:"destination_hostgroup"`
	// 0 or 1
	Apply int `libconfig:"apply" json:"apply"`
	// Comment is metadata about the query rule
	Comment string `libconfig:"comment" json:"comment"`
}

type ProxySqlMySqlUser struct {
	Username         string `libconfig:"username" json:"username"`
	Password         string `libconfig:"password" json:"password"`
	DefaultHostgroup int    `libconfig:"default_hostgroup" json:"default_hostgroup"`
	// 0 or 1
	Active        int    `libconfig:"active" json:"active"`
	InstanceGroup string `json:"instance_group"`
}

// ProxySqlMySqlServer contains data about the sql server
type ProxySqlMySqlServer struct {
	Address        string `libconfig:"address" json:"address"`
	Port           int64  `libconfig:"port" json:"port"`
	Hostgroup      int    `libconfig:"hostgroup" json:"hostgroup"`
	MaxConnections int64  `libconfig:"max_connections" json:"max_connections"`
	Comment        string `libconfig:"comment" json:"comment"`
	UseSSL         int    `libconfig:"use_ssl" json:"use_ssl"`
	// These are more here for future features I'm asking for or updating myself
	// They're omit empty because they're not really supported anywhere, moreso scaffolding
	KeyData  string `json:"key_data,omitempty"`
	CAData   string `json:"ca_data,omitempty"`
	CertData string `json:"cert_data,omitempty"`
}

// ProxySqlConfigMysqlVariables are the variables that get loaded into global_variables that are prefixed with mysql-
type ProxySqlConfigMysqlVariables struct {
	// Threads is the number of background threads that ProxySQL uses in order to process MySQL traffic
	Threads int `libconfig:"threads" json:"threads"`
	// MaxConnections is the maximum number of client connections that the proxy can handle
	MaxConnections int64 `libconfig:"max_connections" json:"max_connections"`
	// DefaultQueryDelay is a simple throttling mechanism for queries to the backends
	DefaultQueryDelay int `libconfig:"default_query_delay" json:"default_query_delay"`
	// DefaultQueryTimeout is an in64 specifying the maximal duration of queries to the backend MySQL servers until ProxySQL
	// should return an error to the MySQL client
	DefaultQueryTimeout int64 `libconfig:"default_query_timeout" json:"default_query_timeout"`
	// HaveCompress is currently unused as per the proxysql docs
	HaveCompress bool `libconfig:"have_compress" json:"have_compress"`
	// PollTimeout is the minimal timeout used by the proxy in order to detect
	// incoming/outgoing traffic via the poll() system call
	PollTimeout int64 `libconfig:"poll_timeout" json:"poll_timeout"`
	// Interfaces is a semicolon-separated list of hostname:port entries for interfaces
	// for incoming MySQL traffic
	Interfaces string `libconfig:"interfaces" json:"interfaces"`
	// DefaultSchema specifies default schema to be used for incoming MySQL client connections
	// which do not specify a schema name
	DefaultSchema string `libconfig:"default_schema" json:"default_schema"`
	// StackSize isn't documented currently, I'll figure this out later
	StackSize int64 `libconfig:"stack_size" json:"stack_size"`
	// ServerVersion is the server version with which the proxy will respond to the clients.
	ServerVersion string `libconfig:"server_version" json:"server_version"`
	// ConnectTimeoutServer is the timeout for a single attempt at connecting to a
	// backend server from the proxy
	ConnectTimeoutServer int64 `libconfig:"connect_timeout_server" json:"connection_timeout_server"`
	// MonitorHistory is the duration for which the events for the checks made
	// by the Monitor module are kept
	MonitorHistory int64 `libconfig:"monitor_history" json:"monitor_history"`
	// MonitorConnectInterval is the interval at which the Monitor module of the
	// proxy will try to connect to all the MySQL servers in order to check
	// whether they are available or not
	MonitorConnectInterval int64 `libconfig:"monitor_connect_interval" json:"monitor_connect_interval"`
	// MonitorPingInterval is the interval at which the Monitor module should ping
	// the backend servers by using the mysql_ping API
	MonitorPingInterval int64 `libconfig:"monitor_ping_interval" json:"monitor_ping_interval"`
	// PingInternalServerMsec isn't documented by proxysql
	PingInternalServerMsec int64 `libconfig:"ping_internal_server_msec" json:"ping_internal_server_msec"`
	// PingTimeoutServer is the timeout allowed for internal pings to keep connections alive
	PingTimeoutServer int `libconfig:"ping_timeout_server" json:"ping_timeout_server"`
	// CommandsStats is not documented by proxysql
	CommandsStats bool `libconfig:"command_stats" json:"command_stats"`
	// SessionsSort controls whether sessions should be processed in the order of waiting time,
	// in order to have a more balanced distribution of traffic among sessions
	SessionsSort bool `libconfig:"sessions_sort" json:"sessions_sort"`
	// MonitorUsername is the username that the Monitor module will use to connect to the backends
	MonitorUsername string `libconfig:"monitor_username" json:"monitor_username"`
	// MonitorPassword is the password for MonitorUsername
	MonitorPassword string `libconfig:"monitor_password" json:"monitor_password"`
	// SSLP2SCert is not used yet, because it assumes all connections will use this
	SSLP2SCert string `libconfig:"ssl_p2s_cert" json:"ssl_p2s_cert"`
	// SSLP2SKey is not used yet, because it assumes all connections will use this
	SSLP2SKey string `libconfig:"ssl_p2s_key" json:"ssl_p2s_key"`
	// SSLP2SCA is not used yet, because it assumes all connections will use this
	SSLP2SCA string `libconfig:"ssl_p2s_ca" json:"ssl_p2s_ca"`
}

// DatabaseHost is used somewhere? Not sure, need to find this
type DatabaseHost struct {
	Name            string
	IpAddress       string
	PublicIPAddress string
}

// NewProxySqlConfig creates an empty proxysql config struct
func NewProxySqlConfig() *ProxySqlConfig {
	return &ProxySqlConfig{}
}

// GetFullKMSName returns the full kms name to use by a kms client
func (psql *ProxySqlConfig) GetFullKMSName() (string, error) {
	if psql.KMSProject == "" {
		return "", errors.New("no project found")
	}
	if psql.KMSLocation == "" {
		return "", errors.New("no location found")
	}
	if psql.KMSKeyRing == "" {
		return "", errors.New("no ring found")
	}
	if psql.KMSKeyName == "" {
		return "", errors.New("no key found")
	}
	if psql.KMSKeyVersion == "" {
		return "", errors.New("no key version found")
	}
	return fmt.Sprintf(KMSProjectFormat, psql.KMSProject, psql.KMSLocation, psql.KMSKeyRing, psql.KMSKeyName, psql.KMSKeyVersion), nil
}

// EncryptPasswords goes through the users and encrypts all of the passwords using
// a public key on KMS.
func (psql *ProxySqlConfig) EncryptPasswords(client *kms.KeyManagementClient) error {
	fullKey, err := psql.GetFullKMSName()
	if err != nil {
		return err
	}
	ctx := context.Background()
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: fullKey,
	})
	if err != nil {
		return fmt.Errorf("failed to get public key %s", err.Error())
	}
	block, _ := pem.Decode([]byte(response.Pem))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not rsa")
	}
	newSqlUserList := []ProxySqlMySqlUser{}
	for _, user := range psql.MySqlUsers {
		plaintext := []byte(user.Password)
		ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, rsaKey, plaintext, nil)
		if err != nil {
			return fmt.Errorf("rsa.EncryptOAEP: %v", err)
		}
		base64EncodedCipherText := base64.URLEncoding.EncodeToString(ciphertext)
		user.Password = base64EncodedCipherText
		newSqlUserList = append(newSqlUserList, user)
	}
	psql.MySqlUsers = newSqlUserList
	return nil
}

// DecryptPasswords gets the kms key and allows us to decrypt the passwords encrypted
// by psql.EncryptPasswords and get the plaintext versions of them so we can add them
// to the kubernetes secret
func (psql *ProxySqlConfig) DecryptPasswords(client *kms.KeyManagementClient) error {
	ctx := context.Background()
	fullKeyName, err := psql.GetFullKMSName()
	if err != nil {
		return err
	}
	newSqlUserList := []ProxySqlMySqlUser{}
	for _, user := range psql.MySqlUsers {
		cipherBytes, _ := base64.URLEncoding.DecodeString(user.Password)
		req := &kmspb.AsymmetricDecryptRequest{
			Name:       fullKeyName,
			Ciphertext: cipherBytes,
		}

		result, err := client.AsymmetricDecrypt(ctx, req)
		if err != nil {
			return err
		}
		user.Password = string(result.Plaintext)
		newSqlUserList = append(newSqlUserList, user)
	}
	psql.MySqlUsers = newSqlUserList
	return nil
}

// ProxySQLKMSOption are options specific to the kms configuration
// since we can set and get these as needed
type ProxySQLKMSOption func(*ProxySqlConfig)

// WithKMSProject sets the project for KMS
func WithKMSProject(project string) ProxySQLKMSOption {
	return func(psql *ProxySqlConfig) {
		psql.KMSProject = project
	}
}

// WithKMSLocation sets the location for KMS
func WithKMSLocation(location string) ProxySQLKMSOption {
	return func(psql *ProxySqlConfig) {
		psql.KMSLocation = location
	}
}

// WithKMSKeyRing sets the key ring name
func WithKMSKeyRing(ring string) ProxySQLKMSOption {
	return func(psql *ProxySqlConfig) {
		psql.KMSKeyRing = ring
	}
}

// WithKMSKeyName sets the key name
func WithKMSKeyName(name string) ProxySQLKMSOption {
	return func(psql *ProxySqlConfig) {
		psql.KMSKeyName = name
	}
}

// WithKMSKeyVersion sets the version number
func WithKMSKeyVersion(version string) ProxySQLKMSOption {
	return func(psql *ProxySqlConfig) {
		psql.KMSKeyVersion = version
	}
}

// WithKMSOpts allows us to set specific kms configurations
func (psql *ProxySqlConfig) WithKMSOpts(opts ...ProxySQLKMSOption) {
	for _, opt := range opts {
		opt(psql)
	}
}

// WithKMSOptsFromEnv takes the kms configuration from the environment and applies them
func (psql *ProxySqlConfig) WithKMSOptsFromEnv() error {
	projectID := os.Getenv(EnvVarProjectID)
	if projectID == "" {
		return fmt.Errorf("no project id found")
	}
	keyLocation := os.Getenv(EnvVarKMSKeyLocation)
	if keyLocation == "" {
		return fmt.Errorf("no key location found")
	}
	ringName := os.Getenv(EnvVarKMSKeyRing)
	if ringName == "" {
		return fmt.Errorf("no ring name found")
	}
	keyName := os.Getenv(EnvVarKMSKeyName)
	if keyName == "" {
		return fmt.Errorf("no key name found")
	}
	keyVersion := os.Getenv(EnvVarKMSKeyVersion)
	if keyVersion == "" {
		return fmt.Errorf("no key version found")
	}
	psql.WithKMSOpts(WithKMSProject(projectID), WithKMSLocation(keyLocation), WithKMSKeyRing(ringName), WithKMSKeyName(keyName), WithKMSKeyVersion(keyVersion))
	return nil
}

// InitDefaults creates a bunch of default stuff to make it easier
// to modify rather than building this all out of the gate.
func (psql *ProxySqlConfig) InitDefaults() {
	server1 := ProxySqlMySqlServer{
		Address:        "1.2.3.4",
		Port:           3306,
		Hostgroup:      5,
		MaxConnections: 100,
		Comment:        "writer",
		UseSSL:         0,
	}
	server2 := ProxySqlMySqlServer{
		Address:        "1.2.3.5",
		Port:           3306,
		Hostgroup:      10,
		MaxConnections: 100,
		Comment:        "reader-one",
		UseSSL:         0,
	}
	server3 := ProxySqlMySqlServer{
		Address:        "1.2.3.6",
		Port:           3306,
		Hostgroup:      10,
		MaxConnections: 100,
		Comment:        "reader-two",
		UseSSL:         0,
	}
	servers := []ProxySqlMySqlServer{server1, server2, server3}

	user1 := ProxySqlMySqlUser{
		Username:         "user",
		Password:         "password",
		DefaultHostgroup: 10,
		Active:           1,
	}
	users := []ProxySqlMySqlUser{user1}
	rule1 := ProxySqlMySqlQueryRule{
		Username:             "user",
		RuleID:               1,
		Active:               1,
		MatchDigest:          "^SELECT .* FOR UPDATE",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "select for update goes to the writer",
	}
	rule2 := ProxySqlMySqlQueryRule{
		Username:             "user",
		RuleID:               2,
		Active:               1,
		MatchDigest:          "^SELECT",
		DestinationHostgroup: 10,
		Apply:                1,
		Comment:              "selects go to the reader",
	}
	rule3 := ProxySqlMySqlQueryRule{
		Username:             "user",
		RuleID:               3,
		Active:               1,
		MatchDigest:          ".*",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "catch-all to writer",
	}
	rule4 := ProxySqlMySqlQueryRule{
		Username:             "user",
		RuleID:               4,
		Active:               1,
		MatchDigest:          "^DELETE",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "deletes go to writer",
	}

	queryRules := []ProxySqlMySqlQueryRule{rule1, rule2, rule3, rule4}
	psql.DataDir = "/var/lib/proxysql"
	psql.AdminVariables = ProxySqlConfigAdminVariables{
		AdminCredentials: "proxysql-admin:adminpassw0rd",
		MysqlIFaces:      "0.0.0.0:6032",
		RefreshInterval:  2000,
	}
	psql.MysqlVariables = ProxySqlConfigMysqlVariables{
		Threads:                4,
		MaxConnections:         2048,
		DefaultQueryDelay:      0,
		DefaultQueryTimeout:    36000000,
		HaveCompress:           true,
		PollTimeout:            2000,
		Interfaces:             "0.0.0.0:6033;/tmp/proxysql.sock",
		DefaultSchema:          "information_schema",
		StackSize:              1048576,
		ServerVersion:          "5.1.30",
		ConnectTimeoutServer:   10000,
		MonitorHistory:         60000,
		MonitorConnectInterval: 200000,
		MonitorPingInterval:    200000,
		PingInternalServerMsec: 10000,
		PingTimeoutServer:      200,
		CommandsStats:          true,
		SessionsSort:           true,
		MonitorUsername:        "proxysql",
		MonitorPassword:        "proxysqlpassw0rd",
	}
	psql.ReadHostGroup = 10
	psql.WriteHostGroup = 5
	psql.MySqlQueryRules = queryRules
	psql.MySqlServers = servers
	psql.MySqlUsers = users
}

func (psql *ProxySqlConfig) MarshallJSON() []byte {
	b, _ := json.MarshalIndent(psql, "", "  ")
	return b
}

// ToLibConfig converts the ProxySqlConfig struct to a libconfig
// byte slice.
// TODO: GCP uses 1:1 for ssl and replica, SSL won't work
//  with proxysql. I have an issue open with them to fix
//  this, or I'll do it myself
//  https://github.com/sysown/proxysql/issues/3331
func (psql *ProxySqlConfig) ToLibConfig() ([]byte, error) {
	te, err := template.New("psql").Parse(`
datadir="{{ .DataDir }}"
admin_variables=
{
  admin_credentials="{{ .AdminVariables.AdminCredentials }}"
  mysql_ifaces="{{ .AdminVariables.MysqlIFaces }}"
  refresh_interval={{ .AdminVariables.RefreshInterval }}
}
mysql_variables=
{
  threads={{ .MysqlVariables.Threads }}
  max_connections={{ .MysqlVariables.MaxConnections }}
  default_query_delay={{ .MysqlVariables.DefaultQueryDelay }}
  default_query_timeout={{ .MysqlVariables.DefaultQueryTimeout }}
  have_compress={{ .MysqlVariables.HaveCompress }}
  poll_timeout={{ .MysqlVariables.PollTimeout }}
  interfaces="{{ .MysqlVariables.Interfaces }}"
  default_schema="{{ .MysqlVariables.DefaultSchema }}"
  stacksize={{ .MysqlVariables.StackSize }}
  server_version="{{ .MysqlVariables.ServerVersion }}"
  connect_timeout_server={{ .MysqlVariables.ConnectTimeoutServer }}
  monitor_history={{ .MysqlVariables.MonitorHistory }}
  monitor_connect_interval={{ .MysqlVariables.MonitorConnectInterval }}
  monitor_ping_interval={{ .MysqlVariables.MonitorPingInterval }}
  ping_interval_server_msec={{ .MysqlVariables.PingInternalServerMsec }}
  ping_timeout_server={{ .MysqlVariables.PingTimeoutServer }}
  commands_stats={{ .MysqlVariables.CommandsStats }}
  sessions_sort={{ .MysqlVariables.SessionsSort }}
  monitor_username="{{ .MysqlVariables.MonitorUsername }}"
  monitor_password="{{ .MysqlVariables.MonitorPassword }}"
  ssl_p2s_cert="{{ .MysqlVariables.SSLP2SCert }}"
  ssl_p2s_key="{{ .MysqlVariables.SSLP2SKey }}"
  ssl_p2s_ca="{{ .MysqlVariables.SSLP2SCA }}"
}
mysql_servers=
(
  {{range $key, $value := .MySqlServers }}{{ if $key }},
  {{ end }}{ address="{{ $value.Address }}" , port={{ $value.Port }} , hostgroup={{ $value.Hostgroup }}, max_connections={{ $value.MaxConnections }}, use_ssl={{ $value.UseSSL }} }{{end}}
)
mysql_users=
(
  {{range $key, $value := .MySqlUsers }}{{ if $key }},
  {{ end }}{ username = "{{ $value.Username }}" , password = "{{ $value.Password }}" , default_hostgroup = {{ $value.DefaultHostgroup }} , active = {{ $value.Active }} }{{end}}
)
mysql_query_rules=
(
  {{range $key, $value :=  .MySqlQueryRules }}{{ if $key }},
  {{ end }}{ rule_id = "{{ $value.RuleID }}" , username="{{ $value.Username }}" , active={{ $value.Active }} , match_digest="{{ $value.MatchDigest }}" , destination_hostgroup={{ .DestinationHostgroup }} , apply={{ $value.Apply }}, comment="{{ $value.Comment }}" }{{end}}
)`)
	if err != nil {
		return nil, err
	}
	output := new(bytes.Buffer)
	err = te.Execute(output, psql)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// AddReadReplica adds a read replica in the form of a ProxySqlMySqlServer
// to the proxysql config
func (psql *ProxySqlConfig) AddReadReplica(readReplica ProxySqlMySqlServer) {
	proxySqlServers := psql.MySqlServers
	proxySqlServers = append(proxySqlServers, readReplica)
	psql.MySqlServers = proxySqlServers
}

// AddDatabaseRequest represents an incoming request from a client
// (like terraform) to the API to create a new instance group in datastore.
// This won't create a deployment of proxysql, so make sure that at least is
// done first.
type AddDatabaseRequest struct {
	// Action is inferred from the request type, this is not used anymore
	// but kept anyway
	Action string `json:"action"`
	// InstanceName is the name of the database group and the name of the
	// writer instance
	InstanceName string `json:"instance_name"`
	// Username is the name of the user that will connect to proxysql and
	// how proxysql will connect to the backend servers
	Username string `json:"username"`
	// Password is the password for Username
	Password string `json:"password"`
	// MasterInstance contains data about the master/writer instances
	MasterInstance AddDatabaseRequestDatabaseInformation `json:"master_instance"`
	// ReadReplicas contains data about the read replicas that aren't created by
	// chester
	ReadReplicas []AddDatabaseRequestDatabaseInformation `json:"read_replicas"`
	// QueryRules contains the query rules to be used by proxysql
	QueryRules []ProxySqlMySqlQueryRule `json:"query_rules,omitempty"`
	// ChesterMetaData contains the chester metadata, which is stuff like base replica name
	// and how many instances we're willing to scale up to.
	ChesterMetaData ChesterMetaData `json:"chester_meta_data"`
	// these next three will be used once proxysql updates to have instance:ssl config
	KeyData  string `json:"key_data"`
	CertData string `json:"cert_data"`
	CAData   string `json:"ca_data"`
	// binary bool, 0 = false, 1 true
	EnableSSL int `json:"enable_ssl"`
}

// AddDatabaseRequestDatabaseInformation contains the bare minimum information
// required to add an instance to an instance group. The rest is inferred from
// the other structs.
type AddDatabaseRequestDatabaseInformation struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// AddDatabaseResponse is the response from the API to the client after
// an instance group is created.
type AddDatabaseResponse struct {
	// Action is inferred from the response type, but here for extra
	// verbosity
	Action string `json:"action"`
	// QueryRules are the query rules were generated, either by the request or
	// auto-generated.
	QueryRules []ProxySqlMySqlQueryRule `json:"query_rules"`
	// InstanceName is the writer instance and the instance group name
	InstanceName string `json:"instance_name"`
	// Username is the username sent in the request object
	Username string `json:"username"`
	// Password always comes back as REDACTED
	Password string `json:"password"`
	// WriteHostGroup is the host group where the writer exists.
	// This is either specified by the requestor or auto-generated
	WriteHostGroup int `json:"write_host_group"`
	// ReadHostGroup is the host group for the readers
	ReadHostGroup int `json:"read_host_group"`
	// SSLEnabled is currently not used, since we need to tweak proxysql first
	SSLEnabled int `json:"ssl_enabled"`
	// ChesterMetaData contains metadata about how chester should handle these instances
	ChesterMetaData ChesterMetaData `json:"chester_meta_data"`
}

// RemoveDatabaseRequest is sent from a client to the API
// when an instance group no longer should be managed by chester
type RemoveDatabaseRequest struct {
	// Action will default to removed, here for verbosity
	Action string `json:"action"`
	// InstanceName specificies which instance group
	InstanceName string `json:"instance_name"`
	// Username isn't needed, since deleting the instance group will delete the
	// associated users from chester
	Username string `json:"username"`
}

// ModifyDatabaseRequest is the request sent from a client to the API
// in order to modify an instance, i.e. if you want to add another permanent
// read replica.
// TODO: allow for multiple users/passwords per database.
type ModifyDatabaseRequest struct {
	// Action will default to 'modify', here for verbosity
	Action string `json:"action"`
	// InstanceName specifies the instance group you want to modify
	InstanceName string `json:"instance_name"`
	// NewUsername is the new user name that will be used from proxysql to connect to the sql instances
	NewUsername string `json:"new_username,omitempty"`
	// NewPassword is the new password that will be associated with this proxysql instance
	NewPassword string `json:"new_password,omitempty"`
	// AddQueryRules is a list of new query rules to add to proxysql
	AddQueryRules []ProxySqlMySqlQueryRule `json:"add_query_rules"`
	// RemoveQueryRules is a list of query rule ids to remove
	RemoveQueryRules []int `json:"remove_query_rules"`
	// ReadReplicas is considered an authoritative list here when sending a modify request
	ReadReplicas []AddDatabaseRequestDatabaseInformation `json:"read_replicas"`
	// ChesterMetaData is an authoritative update to the metadata.
	ChesterMetaData ChesterMetaData `json:"chester_meta_data"`
}

// ModifyUserRequest isn't used, but the endpoints exist for it.
// TODO: Deprecate modify user requests
type ModifyUserRequest struct {
	Action           string `json:"action"`
	Username         string `json:"username"`
	NewUsername      string `json:"new_username,omitempty"`
	Password         string `json:"password,omitempty"`
	InstanceGroup    string `json:"instance_group,omitempty"`
	DefaultHostgroup int    `json:"default_host_group,omitempty"`
}

// InstanceData is a simplified struct for the proxysql config, used primarly
// by client APIs so they don't need to know the entire configuration.
type InstanceData struct {
	// InstanceName is the name of the writer instance and the instace group
	InstanceName string `json:"instance_name"`
	// ReadHostGroup is the host group ID of the read replicas
	ReadHostGroup int `json:"read_hostgroup"`
	// WriteHostGroup is the host group ID of the writer
	WriteHostGroup int `json:"write_hostgroup"`
	// Username is the username that clients will connect to proxysql, and
	// how proxysql will connect to the backends
	Username string `json:"username"`
	// Password is the password for Username
	Password string `json:"password"`
	// QueryRules is the proxysql query rules that the instance group follows
	QueryRules []ProxySqlMySqlQueryRule `json:"query_rules"`
	// MasterInstance is the name and IP address of the writer instance
	MasterInstance AddDatabaseRequestDatabaseInformation `json:"master_instance"`
	// ReadReplicas is a list of instances that are read replicas
	ReadReplicas []AddDatabaseRequestDatabaseInformation `json:"read_replicas"`
	// UseSSL isn't currently used, since there needs to be changes to proxysql in order to facilitate this
	UseSSL int `json:"use_ssl"`
	// ChesterMetaData contains data about how to handle scaling for this instance
	ChesterMetaData ChesterMetaData `json:"chester_meta_data"`
}

// ChesterMetaData is the struct that holds metadata about a specific instance's
// data, currently it's just a map[string]string{} so I have to modify it to use this
type ChesterMetaData struct {
	// InstanceGroup is often just the master instance name, but it's used as the identifier for the proxysql key in datastore
	InstanceGroup string `json:"instance_group"`
	// MaxChesterInstances is the amount of read replicas we can add before we receive an alert.
	MaxChesterInstances int `json:"max_chester_instances"`
}
