package policy

type findingLabel struct {
	rule     string
	evidence string
}

const (
	ruleApplicationCredentialPath = "application_credential_path"
	evidenceApplicationCredential = "application credential path"
	ruleCloudCredentialPath       = "cloud_credential_path"
	evidenceCloudCredentialPath   = "cloud credential path"
	ruleCloudEnvironment          = "cloud_environment"
	evidenceCloudEnvironment      = "cloud credential environment"
	ruleDatabaseCredentialPath    = "database_credential_path"
	evidenceDatabaseCredential    = "database credential path"
	ruleEnvironmentCommand        = "environment_command"
	evidenceEnvironmentCommand    = "environment listing command"
	ruleKubernetesSensitivePath   = "kubernetes_sensitive_path"
	evidenceKubernetesPath        = "kubernetes sensitive path"
	ruleNetworkCommand            = "network_command"
	evidenceNetworkCommand        = "network identity command"
	ruleNetworkIdentityPath       = "network_identity_path"
	evidenceNetworkIdentityPath   = "network identity path"
	rulePrivateKeyInput           = "private_key_input"
	evidencePrivateKeyInput       = "private key input"
	rulePrivateKeyPath            = "private_key_path"
	evidencePrivateKeyPath        = "private key path"
	ruleProcessEnvironmentPath    = "process_environment_path"
	evidenceProcessEnvironment    = "process environment path"
	rulePublicIPLookup            = "public_ip_lookup"
	evidencePublicIPLookup        = "public IP lookup command"
	ruleSSHSensitivePath          = "ssh_sensitive_path"
	evidenceSSHPath               = "ssh sensitive path"
)

var (
	labelApplicationCredentialPath = findingLabel{ruleApplicationCredentialPath, evidenceApplicationCredential}
	labelCloudCredentialPath       = findingLabel{ruleCloudCredentialPath, evidenceCloudCredentialPath}
	labelCloudEnvironment          = findingLabel{ruleCloudEnvironment, evidenceCloudEnvironment}
	labelDatabaseCredentialPath    = findingLabel{ruleDatabaseCredentialPath, evidenceDatabaseCredential}
	labelEnvironmentCommand        = findingLabel{ruleEnvironmentCommand, evidenceEnvironmentCommand}
	labelKubernetesSensitivePath   = findingLabel{ruleKubernetesSensitivePath, evidenceKubernetesPath}
	labelNetworkCommand            = findingLabel{ruleNetworkCommand, evidenceNetworkCommand}
	labelNetworkIdentityPath       = findingLabel{ruleNetworkIdentityPath, evidenceNetworkIdentityPath}
	labelPrivateKeyInput           = findingLabel{rulePrivateKeyInput, evidencePrivateKeyInput}
	labelPrivateKeyPath            = findingLabel{rulePrivateKeyPath, evidencePrivateKeyPath}
	labelProcessEnvironmentPath    = findingLabel{ruleProcessEnvironmentPath, evidenceProcessEnvironment}
	labelPublicIPLookup            = findingLabel{rulePublicIPLookup, evidencePublicIPLookup}
	labelSSHSensitivePath          = findingLabel{ruleSSHSensitivePath, evidenceSSHPath}

	allFindingLabels = []findingLabel{
		labelApplicationCredentialPath,
		labelCloudCredentialPath,
		labelCloudEnvironment,
		labelDatabaseCredentialPath,
		labelEnvironmentCommand,
		labelKubernetesSensitivePath,
		labelNetworkCommand,
		labelNetworkIdentityPath,
		labelPrivateKeyInput,
		labelPrivateKeyPath,
		labelProcessEnvironmentPath,
		labelPublicIPLookup,
		labelSSHSensitivePath,
	}
)

func labeledFinding(category Category, label findingLabel) Finding {
	return Finding{Category: category, Rule: label.rule, Evidence: label.evidence}
}
