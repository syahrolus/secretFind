"""
Secret pattern definitions — 90+ patterns across all major categories.
Each pattern has: id, name, regex, severity, description, tags, confidence, group.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SecretPattern:
    id: str
    name: str
    pattern: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    tags: List[str] = field(default_factory=list)
    confidence: str = "HIGH"   # HIGH | MEDIUM | LOW
    group: int = 0             # capture group that contains the secret value

    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False, compare=False)

    def compile(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.MULTILINE)
        return self._compiled

    def findall(self, text: str) -> List[re.Match]:
        return list(self.compile().finditer(text))


# ---------------------------------------------------------------------------
# FALSE-POSITIVE FILTER — values matching these are skipped
# ---------------------------------------------------------------------------
FP_PATTERNS = re.compile(
    r'^(?:'
    r'x{6,}|0{6,}|1{6,}|a{6,}'                      # repetitive chars
    r'|(?:your|my|the|example|sample|test|dummy|placeholder|replace|changeme|secret|key|token|password|pass|api_?key)[-_]?\w{0,20}'
    r'|<[^>]+>'                                         # <PLACEHOLDER>
    r'|\$\{[^}]+\}'                                     # ${VARIABLE}
    r'|\$[A-Z_]+'                                       # $ENV_VAR
    r'|%[A-Z_]+'                                        # %ENV_VAR%
    r'|\*{4,}'                                          # ****
    r'|https?://localhost'                              # localhost URLs
    r')$',
    re.IGNORECASE,
)


PATTERNS: List[SecretPattern] = [

    # =========================================================================
    # AWS
    # =========================================================================
    SecretPattern(
        id="aws-access-key-id",
        name="AWS Access Key ID",
        pattern=r'(?<![A-Za-z0-9/+])((?:AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16})(?![A-Za-z0-9/+])',
        severity="CRITICAL",
        description="AWS Access Key ID (permanent or session-based)",
        tags=["aws", "cloud", "credential"],
        group=1,
    ),
    SecretPattern(
        id="aws-secret-access-key",
        name="AWS Secret Access Key",
        pattern=r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|(?:aws|amazon)[_\s-]*secret[_\s-]*(?:access[_\s-]*)?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        severity="CRITICAL",
        description="AWS Secret Access Key (40-char base64)",
        tags=["aws", "cloud", "credential"],
        group=1,
    ),
    SecretPattern(
        id="aws-session-token",
        name="AWS Session Token",
        pattern=r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
        severity="CRITICAL",
        description="AWS STS Temporary Session Token",
        tags=["aws", "cloud", "credential"],
        group=1,
    ),
    SecretPattern(
        id="aws-mws-key",
        name="AWS MWS Key",
        pattern=r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        severity="HIGH",
        description="Amazon Marketplace Web Service key",
        tags=["aws", "cloud"],
    ),
    SecretPattern(
        id="aws-s3-credentials-url",
        name="AWS S3 URL with Credentials",
        pattern=r's3://[A-Za-z0-9\-]+:[A-Za-z0-9/+=@]+@[A-Za-z0-9.\-]+',
        severity="HIGH",
        description="S3 URL with embedded credentials",
        tags=["aws", "cloud", "url"],
    ),

    # =========================================================================
    # GCP / Google
    # =========================================================================
    SecretPattern(
        id="gcp-api-key",
        name="Google API Key",
        pattern=r'AIza[0-9A-Za-z\-_]{35}',
        severity="HIGH",
        description="Google Cloud Platform API key",
        tags=["gcp", "google", "cloud"],
    ),
    SecretPattern(
        id="gcp-oauth-client-id",
        name="Google OAuth Client ID",
        pattern=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        severity="MEDIUM",
        description="Google OAuth 2.0 Client ID",
        tags=["gcp", "google", "oauth"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="gcp-service-account-key",
        name="GCP Service Account JSON Key",
        pattern=r'"type"\s*:\s*"service_account"',
        severity="CRITICAL",
        description="GCP Service Account private key JSON (partial match)",
        tags=["gcp", "google", "cloud", "credential"],
        confidence="HIGH",
    ),
    SecretPattern(
        id="firebase-url",
        name="Firebase Database URL",
        pattern=r'https://[a-z0-9-]+\.firebaseio\.com',
        severity="MEDIUM",
        description="Firebase Realtime Database URL (may be publicly accessible)",
        tags=["gcp", "google", "firebase"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="firebase-api-key",
        name="Firebase API Key",
        pattern=r'(?:firebase|FIREBASE)[^"\']*(?:api[_\s-]?key|apiKey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{39})["\']',
        severity="HIGH",
        description="Firebase project API key",
        tags=["gcp", "google", "firebase"],
        group=1,
    ),

    # =========================================================================
    # Azure
    # =========================================================================
    SecretPattern(
        id="azure-storage-connection-string",
        name="Azure Storage Connection String",
        pattern=r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/]{86}==)',
        severity="CRITICAL",
        description="Azure Storage Account connection string with key",
        tags=["azure", "cloud", "credential"],
        group=1,
    ),
    SecretPattern(
        id="azure-client-secret",
        name="Azure Client Secret",
        pattern=r'(?:client[_\s-]?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9~._\-]{34,44})["\']?',
        severity="CRITICAL",
        description="Azure Active Directory Service Principal client secret",
        tags=["azure", "cloud"],
        group=1,
    ),
    SecretPattern(
        id="azure-sas-token",
        name="Azure SAS Token",
        pattern=r'sv=\d{4}-\d{2}-\d{2}&(?:ss|st|spr|sr|sp|se|sig)=[^&\s"\']+(?:&(?:ss|st|spr|sr|sp|se|sig)=[^&\s"\']+){3,}',
        severity="HIGH",
        description="Azure Shared Access Signature (SAS) token",
        tags=["azure", "cloud"],
    ),
    SecretPattern(
        id="azure-servicebus-connection",
        name="Azure Service Bus Connection String",
        pattern=r'Endpoint=sb://[^;]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]+',
        severity="CRITICAL",
        description="Azure Service Bus connection string with shared access key",
        tags=["azure", "cloud"],
    ),
    SecretPattern(
        id="azure-cosmosdb-key",
        name="Azure CosmosDB Key",
        pattern=r'(?:cosmos|COSMOS|cosmosdb|COSMOSDB).*AccountKey=([A-Za-z0-9+/]{88}==)',
        severity="CRITICAL",
        description="Azure CosmosDB account key",
        tags=["azure", "cloud", "database"],
        group=1,
    ),

    # =========================================================================
    # GitHub
    # =========================================================================
    SecretPattern(
        id="github-pat-classic",
        name="GitHub Personal Access Token (Classic)",
        pattern=r'ghp_[A-Za-z0-9]{36}',
        severity="CRITICAL",
        description="GitHub Classic Personal Access Token",
        tags=["github", "token"],
    ),
    SecretPattern(
        id="github-oauth-token",
        name="GitHub OAuth Token",
        pattern=r'gho_[A-Za-z0-9]{36}',
        severity="CRITICAL",
        description="GitHub OAuth token",
        tags=["github", "oauth", "token"],
    ),
    SecretPattern(
        id="github-app-token",
        name="GitHub App Token",
        pattern=r'ghs_[A-Za-z0-9]{36}',
        severity="CRITICAL",
        description="GitHub App installation access token",
        tags=["github", "token"],
    ),
    SecretPattern(
        id="github-refresh-token",
        name="GitHub Refresh Token",
        pattern=r'ghr_[A-Za-z0-9]{36}',
        severity="CRITICAL",
        description="GitHub OAuth refresh token",
        tags=["github", "token"],
    ),
    SecretPattern(
        id="github-fine-grained-pat",
        name="GitHub Fine-Grained PAT",
        pattern=r'github_pat_[A-Za-z0-9_]{82}',
        severity="CRITICAL",
        description="GitHub Fine-Grained Personal Access Token",
        tags=["github", "token"],
    ),

    # =========================================================================
    # GitLab
    # =========================================================================
    SecretPattern(
        id="gitlab-pat",
        name="GitLab Personal Access Token",
        pattern=r'glpat-[A-Za-z0-9\-_]{20}',
        severity="CRITICAL",
        description="GitLab Personal Access Token",
        tags=["gitlab", "token"],
    ),
    SecretPattern(
        id="gitlab-runner-token",
        name="GitLab Runner Registration Token",
        pattern=r'glrt-[A-Za-z0-9\-_]{20}',
        severity="HIGH",
        description="GitLab Runner Registration Token",
        tags=["gitlab", "cicd"],
    ),
    SecretPattern(
        id="gitlab-pipeline-trigger",
        name="GitLab Pipeline Trigger Token",
        pattern=r'glptt-[A-Za-z0-9]{40}',
        severity="HIGH",
        description="GitLab Pipeline Trigger Token",
        tags=["gitlab", "cicd"],
    ),
    SecretPattern(
        id="gitlab-deploy-token",
        name="GitLab Deploy Token",
        pattern=r'gldt-[A-Za-z0-9\-_]{20}',
        severity="HIGH",
        description="GitLab Deploy Token",
        tags=["gitlab", "token"],
    ),

    # =========================================================================
    # Slack
    # =========================================================================
    SecretPattern(
        id="slack-bot-token",
        name="Slack Bot OAuth Token",
        pattern=r'xoxb-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[A-Za-z0-9]{24,32}',
        severity="CRITICAL",
        description="Slack Bot OAuth token (full workspace access for a bot)",
        tags=["slack", "token"],
    ),
    SecretPattern(
        id="slack-user-token",
        name="Slack User OAuth Token",
        pattern=r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32,64}',
        severity="CRITICAL",
        description="Slack User OAuth token (acts as a real user)",
        tags=["slack", "token"],
    ),
    SecretPattern(
        id="slack-app-token",
        name="Slack App-Level Token",
        pattern=r'xapp-\d-[A-Z0-9]{10,13}-\d{13}-[a-z0-9]{64}',
        severity="CRITICAL",
        description="Slack app-level token (WebSocket connections)",
        tags=["slack", "token"],
    ),
    SecretPattern(
        id="slack-webhook",
        name="Slack Incoming Webhook URL",
        pattern=r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24,32}',
        severity="HIGH",
        description="Slack Incoming Webhook URL (can post messages to a channel)",
        tags=["slack", "webhook"],
    ),

    # =========================================================================
    # Discord
    # =========================================================================
    SecretPattern(
        id="discord-bot-token",
        name="Discord Bot Token",
        pattern=r'(?:discord[^"\'\n]{0,20}["\']|Bot\s)([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})',
        severity="CRITICAL",
        description="Discord Bot Token (full bot access)",
        tags=["discord", "token"],
        group=1,
    ),
    SecretPattern(
        id="discord-webhook",
        name="Discord Webhook URL",
        pattern=r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{68}',
        severity="HIGH",
        description="Discord Webhook URL",
        tags=["discord", "webhook"],
    ),
    SecretPattern(
        id="discord-client-secret",
        name="Discord Client Secret",
        pattern=r'(?:discord|DISCORD)[^"\'\n]{0,30}client[_\s-]?secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32})["\']?',
        severity="CRITICAL",
        description="Discord application client secret",
        tags=["discord", "oauth"],
        group=1,
    ),

    # =========================================================================
    # Stripe / Payments
    # =========================================================================
    SecretPattern(
        id="stripe-secret-key",
        name="Stripe Live Secret Key",
        pattern=r'sk_live_[0-9a-zA-Z]{24,99}',
        severity="CRITICAL",
        description="Stripe live secret key (full API access, can charge cards)",
        tags=["stripe", "payment", "credential"],
    ),
    SecretPattern(
        id="stripe-restricted-key",
        name="Stripe Restricted Key",
        pattern=r'rk_live_[0-9a-zA-Z]{24,99}',
        severity="CRITICAL",
        description="Stripe restricted live key",
        tags=["stripe", "payment"],
    ),
    SecretPattern(
        id="stripe-publishable-key",
        name="Stripe Live Publishable Key",
        pattern=r'pk_live_[0-9a-zA-Z]{24,99}',
        severity="MEDIUM",
        description="Stripe live publishable key (indicates production environment)",
        tags=["stripe", "payment"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="stripe-test-secret",
        name="Stripe Test Secret Key",
        pattern=r'sk_test_[0-9a-zA-Z]{24,99}',
        severity="LOW",
        description="Stripe test secret key",
        tags=["stripe", "payment", "test"],
        confidence="HIGH",
    ),
    SecretPattern(
        id="square-oauth-secret",
        name="Square OAuth Application Secret",
        pattern=r'sq0csp-[0-9A-Za-z\-_]{43}',
        severity="CRITICAL",
        description="Square OAuth application secret",
        tags=["square", "payment"],
    ),
    SecretPattern(
        id="paypal-braintree-token",
        name="PayPal/Braintree Access Token",
        pattern=r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        severity="CRITICAL",
        description="PayPal/Braintree production access token",
        tags=["paypal", "braintree", "payment"],
    ),

    # =========================================================================
    # Twilio
    # =========================================================================
    SecretPattern(
        id="twilio-account-sid",
        name="Twilio Account SID",
        pattern=r'AC[0-9a-fA-F]{32}',
        severity="MEDIUM",
        description="Twilio Account SID (not sensitive alone, but combined with auth token is critical)",
        tags=["twilio", "communication"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="twilio-auth-token",
        name="Twilio Auth Token",
        pattern=r'(?:twilio|TWILIO)[^"\'\n]{0,40}["\']([0-9a-fA-F]{32})["\']',
        severity="CRITICAL",
        description="Twilio Auth Token",
        tags=["twilio", "communication", "credential"],
        group=1,
    ),
    SecretPattern(
        id="twilio-api-key",
        name="Twilio API Key SID",
        pattern=r'SK[0-9a-fA-F]{32}',
        severity="HIGH",
        description="Twilio API Key SID",
        tags=["twilio", "communication"],
        confidence="MEDIUM",
    ),

    # =========================================================================
    # Email services
    # =========================================================================
    SecretPattern(
        id="sendgrid-api-key",
        name="SendGrid API Key",
        pattern=r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        severity="HIGH",
        description="SendGrid API key (email sending access)",
        tags=["sendgrid", "email"],
    ),
    SecretPattern(
        id="mailgun-api-key",
        name="Mailgun API Key",
        pattern=r'key-[0-9a-zA-Z]{32}',
        severity="HIGH",
        description="Mailgun API key",
        tags=["mailgun", "email"],
    ),
    SecretPattern(
        id="mailchimp-api-key",
        name="Mailchimp API Key",
        pattern=r'[0-9a-f]{32}-us[0-9]{1,2}',
        severity="HIGH",
        description="Mailchimp API key",
        tags=["mailchimp", "email"],
    ),
    SecretPattern(
        id="postmark-server-token",
        name="Postmark Server Token",
        pattern=r'(?:postmark|POSTMARK)[^"\'\n]{0,30}["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']',
        severity="HIGH",
        description="Postmark email service server token",
        tags=["postmark", "email"],
        group=1,
    ),

    # =========================================================================
    # Private Keys & Certificates
    # =========================================================================
    SecretPattern(
        id="private-key-rsa",
        name="RSA Private Key",
        pattern=r'-----BEGIN RSA PRIVATE KEY-----',
        severity="CRITICAL",
        description="PKCS#1 RSA Private Key",
        tags=["crypto", "key", "private-key", "pem"],
    ),
    SecretPattern(
        id="private-key-ec",
        name="EC Private Key",
        pattern=r'-----BEGIN EC PRIVATE KEY-----',
        severity="CRITICAL",
        description="Elliptic Curve Private Key",
        tags=["crypto", "key", "private-key", "pem"],
    ),
    SecretPattern(
        id="private-key-dsa",
        name="DSA Private Key",
        pattern=r'-----BEGIN DSA PRIVATE KEY-----',
        severity="CRITICAL",
        description="DSA Private Key",
        tags=["crypto", "key", "private-key", "pem"],
    ),
    SecretPattern(
        id="private-key-openssh",
        name="OpenSSH Private Key",
        pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
        severity="CRITICAL",
        description="OpenSSH Private Key (Ed25519, ECDSA, RSA, etc.)",
        tags=["crypto", "key", "private-key", "ssh"],
    ),
    SecretPattern(
        id="private-key-pkcs8",
        name="PKCS#8 Private Key",
        pattern=r'-----BEGIN PRIVATE KEY-----',
        severity="CRITICAL",
        description="PKCS#8 unencrypted private key",
        tags=["crypto", "key", "private-key", "pem"],
    ),
    SecretPattern(
        id="private-key-encrypted-pkcs8",
        name="Encrypted PKCS#8 Private Key",
        pattern=r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        severity="HIGH",
        description="PKCS#8 encrypted private key (password-protected)",
        tags=["crypto", "key", "private-key", "pem"],
    ),
    SecretPattern(
        id="pgp-private-key-block",
        name="PGP Private Key Block",
        pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        severity="CRITICAL",
        description="PGP/GPG Private Key Block",
        tags=["crypto", "pgp", "key", "private-key"],
    ),
    SecretPattern(
        id="age-secret-key",
        name="age Encryption Secret Key",
        pattern=r'AGE-SECRET-KEY-[A-Z0-9]{59}',
        severity="CRITICAL",
        description="age file encryption tool secret key",
        tags=["crypto", "key", "age"],
    ),

    # =========================================================================
    # JWT
    # =========================================================================
    SecretPattern(
        id="jwt-token",
        name="JSON Web Token (JWT)",
        pattern=r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        severity="MEDIUM",
        description="JWT token — may be a valid session, carry sensitive claims, or expose a weak HS256 secret",
        tags=["jwt", "auth", "token"],
        confidence="MEDIUM",
    ),

    # =========================================================================
    # Database connection strings
    # =========================================================================
    SecretPattern(
        id="db-postgresql",
        name="PostgreSQL Connection String",
        pattern=r'postgresql(?:ql)?://[^:\s"\']+:[^@\s"\']+@[^\s"\']+',
        severity="CRITICAL",
        description="PostgreSQL connection string with embedded credentials",
        tags=["database", "postgresql"],
    ),
    SecretPattern(
        id="db-mysql",
        name="MySQL Connection String",
        pattern=r'mysql(?:2)?://[^:\s"\']+:[^@\s"\']+@[^\s"\']+',
        severity="CRITICAL",
        description="MySQL connection string with embedded credentials",
        tags=["database", "mysql"],
    ),
    SecretPattern(
        id="db-mongodb",
        name="MongoDB Connection String",
        pattern=r'mongodb(?:\+srv)?://[^:\s"\']+:[^@\s"\']+@[^\s"\']+',
        severity="CRITICAL",
        description="MongoDB connection string with embedded credentials",
        tags=["database", "mongodb"],
    ),
    SecretPattern(
        id="db-redis",
        name="Redis Connection String with Password",
        pattern=r'redis(?:s)?://[^:\s"\']*:[^@\s"\']+@[^\s"\']+',
        severity="HIGH",
        description="Redis connection string with password",
        tags=["database", "redis"],
    ),
    SecretPattern(
        id="db-elasticsearch",
        name="Elasticsearch Connection String",
        pattern=r'https?://[^:\s"\']+:[^@\s"\']+@[^\s"\']*(?:920[023]|elastic)[^\s"\']*',
        severity="HIGH",
        description="Elasticsearch connection string with credentials",
        tags=["database", "elasticsearch"],
    ),
    SecretPattern(
        id="db-mssql-connection-string",
        name="MSSQL Connection String",
        pattern=r'(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:Database|Initial Catalog)\s*=\s*[^;]+;\s*(?:User Id|UID|User)\s*=\s*[^;]+;\s*Password\s*=\s*[^;"\'\n]+',
        severity="CRITICAL",
        description="Microsoft SQL Server connection string with credentials",
        tags=["database", "mssql"],
    ),
    SecretPattern(
        id="db-oracle-connection",
        name="Oracle DB Connection String",
        pattern=r'(?:oracle|jdbc:oracle)[^@\s"\']*:[^@\s"\']+@[^\s"\']+',
        severity="CRITICAL",
        description="Oracle database connection string with credentials",
        tags=["database", "oracle"],
    ),

    # =========================================================================
    # NPM / Node / Python packages
    # =========================================================================
    SecretPattern(
        id="npm-access-token",
        name="NPM Access Token",
        pattern=r'npm_[A-Za-z0-9]{36}',
        severity="HIGH",
        description="NPM automation/publish access token",
        tags=["npm", "node", "registry"],
    ),
    SecretPattern(
        id="npm-rc-auth-token",
        name="NPM Auth Token in .npmrc",
        pattern=r'//registry\.npmjs\.org/:_authToken\s*=\s*([^\s\n]+)',
        severity="HIGH",
        description="NPM auth token embedded in .npmrc",
        tags=["npm", "node"],
        group=1,
    ),
    SecretPattern(
        id="pypi-api-token",
        name="PyPI API Token",
        pattern=r'pypi-[A-Za-z0-9_\-]{64,192}',
        severity="HIGH",
        description="PyPI package upload API token",
        tags=["pypi", "python", "registry"],
    ),

    # =========================================================================
    # AI / ML services
    # =========================================================================
    SecretPattern(
        id="openai-api-key",
        name="OpenAI API Key",
        pattern=r'sk-(?:proj-)?[A-Za-z0-9]{48}',
        severity="HIGH",
        description="OpenAI API key (access to GPT models, billed per token)",
        tags=["openai", "ai"],
    ),
    SecretPattern(
        id="anthropic-api-key",
        name="Anthropic / Claude API Key",
        pattern=r'sk-ant-api\d{2}-[A-Za-z0-9\-_]{93,}AA',
        severity="HIGH",
        description="Anthropic Claude API key",
        tags=["anthropic", "ai"],
    ),
    SecretPattern(
        id="huggingface-api-token",
        name="Hugging Face API Token",
        pattern=r'hf_[A-Za-z0-9]{34}',
        severity="HIGH",
        description="Hugging Face Hub API token",
        tags=["huggingface", "ai"],
    ),
    SecretPattern(
        id="replicate-api-token",
        name="Replicate API Token",
        pattern=r'r8_[A-Za-z0-9]{40}',
        severity="HIGH",
        description="Replicate AI API token",
        tags=["replicate", "ai"],
    ),
    SecretPattern(
        id="cohere-api-key",
        name="Cohere API Key",
        pattern=r'(?:cohere|COHERE)[^"\'\n]{0,20}["\']([A-Za-z0-9]{40})["\']',
        severity="HIGH",
        description="Cohere API key",
        tags=["cohere", "ai"],
        group=1,
    ),

    # =========================================================================
    # Social Media APIs
    # =========================================================================
    SecretPattern(
        id="twitter-bearer-token",
        name="Twitter/X Bearer Token",
        pattern=r'AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{33,50}',
        severity="HIGH",
        description="Twitter/X API v2 Bearer Token",
        tags=["twitter", "x", "social"],
    ),
    SecretPattern(
        id="facebook-access-token",
        name="Facebook/Meta Access Token",
        pattern=r'EAA[A-Za-z0-9]{50,200}',
        severity="HIGH",
        description="Facebook/Meta API access token",
        tags=["facebook", "meta", "social"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="instagram-access-token",
        name="Instagram Access Token",
        pattern=r'IGQ[A-Za-z0-9_\-]{100,200}',
        severity="HIGH",
        description="Instagram API access token",
        tags=["instagram", "meta", "social"],
    ),
    SecretPattern(
        id="linkedin-client-secret",
        name="LinkedIn Client Secret",
        pattern=r'(?:linkedin|LINKEDIN)[^"\'\n]{0,30}(?:secret|key)\s*[=:]\s*["\']?([A-Za-z0-9]{16})["\']?',
        severity="HIGH",
        description="LinkedIn OAuth Client Secret",
        tags=["linkedin", "social"],
        group=1,
    ),

    # =========================================================================
    # Cloud infrastructure (other providers)
    # =========================================================================
    SecretPattern(
        id="digitalocean-pat",
        name="DigitalOcean Personal Access Token",
        pattern=r'dop_v1_[a-f0-9]{64}',
        severity="CRITICAL",
        description="DigitalOcean Personal Access Token (full account access)",
        tags=["digitalocean", "cloud"],
    ),
    SecretPattern(
        id="digitalocean-oauth-token",
        name="DigitalOcean OAuth Token",
        pattern=r'doo_v1_[a-f0-9]{64}',
        severity="CRITICAL",
        description="DigitalOcean OAuth Token",
        tags=["digitalocean", "cloud"],
    ),
    SecretPattern(
        id="cloudflare-api-key",
        name="Cloudflare API Key",
        pattern=r'(?:cloudflare|CLOUDFLARE)[^"\'\n]{0,30}(?:global[_\s]?api[_\s]?key|api[_\s]?key|x-auth-key)\s*[=:]\s*["\']?([0-9a-f]{37})["\']?',
        severity="CRITICAL",
        description="Cloudflare Global API Key (full account access)",
        tags=["cloudflare", "cloud"],
        group=1,
    ),
    SecretPattern(
        id="cloudflare-api-token",
        name="Cloudflare API Token",
        pattern=r'(?:cloudflare|CLOUDFLARE|CF_API_TOKEN)[^"\'\n]{0,20}["\']([A-Za-z0-9_\-]{40})["\']',
        severity="HIGH",
        description="Cloudflare scoped API Token",
        tags=["cloudflare", "cloud"],
        group=1,
    ),
    SecretPattern(
        id="linode-api-token",
        name="Linode/Akamai Cloud API Token",
        pattern=r'(?:linode|LINODE)[^"\'\n]{0,20}["\']([A-Za-z0-9]{64})["\']',
        severity="HIGH",
        description="Linode (now Akamai) Cloud API token",
        tags=["linode", "akamai", "cloud"],
        group=1,
    ),

    # =========================================================================
    # Monitoring / Observability
    # =========================================================================
    SecretPattern(
        id="datadog-api-key",
        name="Datadog API Key",
        pattern=r'(?:DD_API_KEY|datadog[^"\'\n]{0,20}api[_\s-]?key)\s*[=:]\s*["\']?([0-9a-fA-F]{32})["\']?',
        severity="HIGH",
        description="Datadog API key",
        tags=["datadog", "monitoring"],
        group=1,
    ),
    SecretPattern(
        id="new-relic-license-key",
        name="New Relic License Key",
        pattern=r'NRAK-[A-Z0-9]{27}',
        severity="HIGH",
        description="New Relic ingest license key",
        tags=["newrelic", "monitoring"],
    ),
    SecretPattern(
        id="new-relic-api-key",
        name="New Relic User API Key",
        pattern=r'NRAA-[A-Za-z0-9]{27}',
        severity="HIGH",
        description="New Relic user API key",
        tags=["newrelic", "monitoring"],
    ),
    SecretPattern(
        id="grafana-api-key",
        name="Grafana API Key / Service Account Token",
        pattern=r'(?:glc|glsa)_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}',
        severity="HIGH",
        description="Grafana Cloud API key or service account token",
        tags=["grafana", "monitoring"],
    ),
    SecretPattern(
        id="pagerduty-api-key",
        name="PagerDuty API Key",
        pattern=r'(?:pagerduty|PAGERDUTY|PAGERDUTY_API_KEY)[^"\'\n]{0,20}["\']([A-Za-z0-9+_\-]{20})["\']',
        severity="HIGH",
        description="PagerDuty REST API key",
        tags=["pagerduty", "monitoring"],
        group=1,
    ),

    # =========================================================================
    # CI/CD
    # =========================================================================
    SecretPattern(
        id="circleci-api-token",
        name="CircleCI API Token",
        pattern=r'(?:circleci|CIRCLECI|CIRCLE_TOKEN)[^"\'\n]{0,20}["\']([0-9a-fA-F]{40})["\']',
        severity="HIGH",
        description="CircleCI personal API token",
        tags=["circleci", "cicd"],
        group=1,
    ),
    SecretPattern(
        id="travis-ci-token",
        name="Travis CI API Token",
        pattern=r'(?:travis|TRAVIS_TOKEN)[^"\'\n]{0,20}["\']([A-Za-z0-9]{22})["\']',
        severity="HIGH",
        description="Travis CI API token",
        tags=["travis", "cicd"],
        group=1,
    ),

    # =========================================================================
    # E-Commerce
    # =========================================================================
    SecretPattern(
        id="shopify-access-token",
        name="Shopify Access Token",
        pattern=r'shpat_[A-Fa-f0-9]{32}',
        severity="CRITICAL",
        description="Shopify Admin API access token",
        tags=["shopify", "ecommerce"],
    ),
    SecretPattern(
        id="shopify-private-app-password",
        name="Shopify Private App Password",
        pattern=r'shppa_[A-Fa-f0-9]{32}',
        severity="CRITICAL",
        description="Shopify private app password",
        tags=["shopify", "ecommerce"],
    ),
    SecretPattern(
        id="shopify-shared-secret",
        name="Shopify Shared Secret",
        pattern=r'shpss_[A-Fa-f0-9]{32}',
        severity="HIGH",
        description="Shopify partner shared secret",
        tags=["shopify", "ecommerce"],
    ),
    SecretPattern(
        id="shopify-custom-app-token",
        name="Shopify Custom App Token",
        pattern=r'shpca_[A-Fa-f0-9]{32}',
        severity="CRITICAL",
        description="Shopify custom app token",
        tags=["shopify", "ecommerce"],
    ),

    # =========================================================================
    # CRM / Support / Productivity
    # =========================================================================
    SecretPattern(
        id="hubspot-api-key",
        name="HubSpot API Key",
        pattern=r'(?:hubspot|HUBSPOT|HUBAPI)[^"\'\n]{0,20}["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']',
        severity="HIGH",
        description="HubSpot API key",
        tags=["hubspot", "crm"],
        group=1,
    ),
    SecretPattern(
        id="salesforce-access-token",
        name="Salesforce OAuth Access Token",
        pattern=r'00[A-Za-z0-9]{15}![A-Za-z0-9._]{90,130}',
        severity="CRITICAL",
        description="Salesforce OAuth access token",
        tags=["salesforce", "crm"],
    ),
    SecretPattern(
        id="notion-api-key",
        name="Notion Integration Token",
        pattern=r'secret_[A-Za-z0-9]{43}',
        severity="HIGH",
        description="Notion internal integration token",
        tags=["notion", "productivity"],
    ),
    SecretPattern(
        id="linear-api-key",
        name="Linear API Key",
        pattern=r'lin_api_[A-Za-z0-9]{40}',
        severity="HIGH",
        description="Linear project management API key",
        tags=["linear", "productivity"],
    ),

    # =========================================================================
    # HashiCorp / Secrets Managers
    # =========================================================================
    SecretPattern(
        id="vault-token",
        name="HashiCorp Vault Token",
        pattern=r'\bhvs\.[A-Za-z0-9]{24,}\b',
        severity="CRITICAL",
        description="HashiCorp Vault service token",
        tags=["vault", "hashicorp"],
    ),
    SecretPattern(
        id="terraform-cloud-token",
        name="Terraform Cloud API Token",
        pattern=r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}',
        severity="CRITICAL",
        description="Terraform Cloud / HCP Terraform API token",
        tags=["terraform", "hashicorp"],
    ),
    SecretPattern(
        id="doppler-service-token",
        name="Doppler Service Token",
        pattern=r'dp\.st\.[A-Za-z0-9_]{43}',
        severity="HIGH",
        description="Doppler secrets manager service token",
        tags=["doppler", "secrets"],
    ),

    # =========================================================================
    # Identity / Auth
    # =========================================================================
    SecretPattern(
        id="okta-api-token",
        name="Okta API Token",
        pattern=r'00[A-Za-z0-9\-_]{40}',
        severity="HIGH",
        description="Okta SSWS API token",
        tags=["okta", "identity"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="auth0-client-secret",
        name="Auth0 Client Secret",
        pattern=r'(?:auth0|AUTH0)[^"\'\n]{0,30}(?:secret|client_secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{64})["\']?',
        severity="CRITICAL",
        description="Auth0 application client secret",
        tags=["auth0", "identity"],
        group=1,
    ),

    # =========================================================================
    # Artifact Registries / Container
    # =========================================================================
    SecretPattern(
        id="docker-config-auth",
        name="Docker Registry Auth (base64)",
        pattern=r'"auth"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"',
        severity="CRITICAL",
        description="Docker registry base64-encoded username:password in config.json",
        tags=["docker", "registry", "credential"],
        group=1,
    ),
    SecretPattern(
        id="artifactory-api-token",
        name="JFrog Artifactory API Token",
        pattern=r'(?:artifactory|ARTIFACTORY)[^"\'\n]{0,30}["\']([A-Za-z0-9]{73})["\']',
        severity="HIGH",
        description="JFrog Artifactory API token",
        tags=["artifactory", "registry"],
        group=1,
    ),

    # =========================================================================
    # Generic / catch-all patterns (lower confidence)
    # =========================================================================
    SecretPattern(
        id="generic-password-in-code",
        name="Hardcoded Password",
        pattern=r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'$\{\}\s%<>]{8,})["\']',
        severity="HIGH",
        description="Hardcoded password in source code",
        tags=["password", "generic", "hardcoded"],
        confidence="MEDIUM",
        group=1,
    ),
    SecretPattern(
        id="generic-secret-in-code",
        name="Hardcoded Secret",
        pattern=r'(?<![\w])(?:secret|SECRET)\s*[=:]\s*["\']([^"\'$\{\}\s%<>]{8,})["\']',
        severity="HIGH",
        description="Hardcoded secret value in source code",
        tags=["secret", "generic", "hardcoded"],
        confidence="MEDIUM",
        group=1,
    ),
    SecretPattern(
        id="generic-api-key-in-code",
        name="Hardcoded API Key",
        pattern=r'(?:api[_\s-]?key|apikey|API_KEY)\s*[=:]\s*["\']([^"\'$\{\}\s%<>]{16,})["\']',
        severity="HIGH",
        description="Hardcoded API key in source code",
        tags=["api-key", "generic", "hardcoded"],
        confidence="MEDIUM",
        group=1,
    ),
    SecretPattern(
        id="generic-token-in-code",
        name="Hardcoded Token",
        pattern=r'(?<![\w])(?:token|TOKEN|access_token|auth_token)\s*[=:]\s*["\']([^"\'$\{\}\s%<>]{16,})["\']',
        severity="MEDIUM",
        description="Hardcoded token value in source code",
        tags=["token", "generic", "hardcoded"],
        confidence="LOW",
        group=1,
    ),
    SecretPattern(
        id="basic-auth-in-url",
        name="Credentials Embedded in URL",
        pattern=r'https?://(?!localhost)[A-Za-z0-9\-_%]+:[^@\s"\']{4,}@[A-Za-z0-9\-_.]+',
        severity="HIGH",
        description="URL with embedded username:password credentials",
        tags=["auth", "url", "credential"],
        confidence="MEDIUM",
    ),
    SecretPattern(
        id="private-key-in-env",
        name="Private Key in Environment Variable",
        pattern=r'(?:PRIVATE_KEY|private_key)\s*[=:]\s*["\']?(-----BEGIN[^-]+PRIVATE KEY-----)',
        severity="CRITICAL",
        description="Private key embedded in environment variable assignment",
        tags=["crypto", "key", "env"],
        group=1,
    ),
]

# Build a lookup by ID for fast access
PATTERNS_BY_ID: dict[str, SecretPattern] = {p.id: p for p in PATTERNS}
