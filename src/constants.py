"""Git Secrets Scanner - Constants"""

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Secret patterns to detect
SECRET_PATTERNS = {
    'aws_access_key': {
        'pattern': r'AKIA[0-9A-Z]{16}',
        'severity': 'critical',
        'description': 'AWS Access Key ID'
    },
    'aws_secret_key': {
        'pattern': r'[A-Za-z0-9/+=]{40}',
        'severity': 'critical',
        'description': 'AWS Secret Access Key'
    },
    'github_token': {
        'pattern': r'ghp_[A-Za-z0-9_]{36}',
        'severity': 'critical',
        'description': 'GitHub Personal Access Token'
    },
    'github_oauth': {
        'pattern': r'gho_[A-Za-z0-9_]{36}',
        'severity': 'critical',
        'description': 'GitHub OAuth Token'
    },
    'google_api_key': {
        'pattern': r'AIza[0-9A-Za-z\-_]{35}',
        'severity': 'high',
        'description': 'Google API Key'
    },
    'stripe_key': {
        'pattern': r'sk_live_[0-9a-zA-Z]{24}',
        'severity': 'critical',
        'description': 'Stripe Secret Key'
    },
    'stripe_publishable': {
        'pattern': r'pk_live_[0-9a-zA-Z]{24}',
        'severity': 'medium',
        'description': 'Stripe Publishable Key'
    },
    'slack_token': {
        'pattern': r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        'severity': 'high',
        'description': 'Slack Token'
    },
    'private_key': {
        'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'severity': 'critical',
        'description': 'Private Key'
    },
    'password_in_url': {
        'pattern': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}',
        'severity': 'high',
        'description': 'Password in URL'
    },
    'jwt_token': {
        'pattern': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'severity': 'medium',
        'description': 'JWT Token'
    },
    'generic_secret': {
        'pattern': r'(?i)(password|secret|api_key|apikey|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
        'severity': 'medium',
        'description': 'Generic Secret Assignment'
    }
}

# Files to ignore
IGNORE_PATTERNS = [
    r'\.git/',
    r'node_modules/',
    r'__pycache__/',
    r'\.pyc$',
    r'\.min\.js$',
    r'package-lock\.json$',
    r'yarn\.lock$',
    r'\.svg$',
    r'\.png$',
    r'\.jpg$',
    r'\.ico$'
]
