mod errors;
pub use errors::GitHubOIDCError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

/// Represents a JSON Web Key (JWK) used for token validation.
///
/// A JWK is a digital secure key used in secure web communications.
/// It contains all the important details about the key, such as what it's for
/// and how it works. This information helps websites verify users.
#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    /// Key type (e.g., "RSA")
    pub kty: String,
    /// Intended use of the key (e.g., "sig" for signature)
    pub use_: Option<String>,
    /// Unique identifier for the key
    pub kid: String,
    /// Algorithm used with this key (e.g., "RS256")
    pub alg: Option<String>,
    /// RSA public key modulus (base64url-encoded)
    pub n: String,
    /// RSA public key exponent (base64url-encoded)
    pub e: String,
    /// X.509 certificate chain (optional)
    pub x5c: Option<Vec<String>>,
    /// X.509 certificate SHA-1 thumbprint (optional)
    pub x5t: Option<String>,
    /// X.509 certificate SHA-256 thumbprint (optional)
    pub x5t_s256: Option<String>,
}

/// Represents a set of JSON Web Keys (JWKS) used for GitHub token validation.
///
/// This structure is crucial for GitHub Actions authentication because:
///
/// 1. GitHub Key Rotation: GitHub rotates its keys for security,
///    and having multiple keys allows your application to validate
///    tokens continuously during these changes.
///
/// 2. Multiple Environments: Different GitHub environments (like production and development)
///    might use different keys. A set of keys allows your app to work across these environments.
///
/// 3. Fallback Mechanism: If one key fails for any reason, your app can try others in the set.
///
/// Think of it like a key ring for a building manager. They don't just carry one key,
/// but a set of keys for different doors or areas.
#[derive(Debug, Serialize, Deserialize)]
pub struct GithubJWKS {
    /// Vector of JSON Web Keys
    pub keys: Vec<JWK>,
}

/// Represents the claims contained in a GitHub Actions JWT (JSON Web Token).
///
/// When a GitHub Actions workflow runs, it receives a token with these claims.
/// This struct helps decode and access the information from that token.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubClaims {
    /// The subject of the token (e.g. the GitHub Actions runner ID).
    pub sub: String,

    /// The full name of the repository.
    pub repository: String,

    /// The owner of the repository.
    pub repository_owner: String,

    /// A reference to the specific job and workflow.
    pub job_workflow_ref: String,

    /// The timestamp when the token was issued.
    pub iat: u64,
}

/// Default URL for fetching GitHub OIDC tokens
pub const DEFAULT_GITHUB_OIDC_URL: &str = "https://token.actions.githubusercontent.com";

/// Fetches the JSON Web Key Set (JWKS) from the specified OIDC URL.
///
/// # Arguments
///
/// * `oidc_url` - The base URL of the OpenID Connect provider (GitHub by default)
///
/// # Returns
///
/// * `Result<GithubJWKS, GitHubOIDCError>` - A Result containing the fetched JWKS if successful,
///   or an error if the fetch or parsing fails
///
/// # Example
///
/// ```
/// use github_oidc::{fetch_jwks, DEFAULT_GITHUB_OIDC_URL};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let jwks = fetch_jwks(DEFAULT_GITHUB_OIDC_URL).await?;
///     println!("JWKS: {:?}", jwks);
///     Ok(())
/// }
/// ```
pub async fn fetch_jwks(oidc_url: &str) -> Result<GithubJWKS, GitHubOIDCError> {
    info!("Fetching JWKS from {}", oidc_url);
    let client = reqwest::Client::new();
    let jwks_url = format!("{}/.well-known/jwks", oidc_url);
    match client.get(&jwks_url).send().await {
        Ok(response) => match response.json::<GithubJWKS>().await {
            Ok(jwks) => {
                info!("JWKS fetched successfully");
                Ok(jwks)
            }
            Err(e) => {
                error!("Failed to parse JWKS response: {:?}", e);
                Err(GitHubOIDCError::JWKSParseError(e.to_string()))
            }
        },
        Err(e) => {
            error!("Failed to fetch JWKS: {:?}", e);
            Err(GitHubOIDCError::JWKSFetchError(e.to_string()))
        }
    }
}

/// Configuration options for GitHub OIDC token validation
#[derive(Debug, Clone, Default)]
pub struct GitHubOIDCConfig {
    /// Expected audience for the token
    pub audience: Option<String>,
    /// Expected repository for the token
    pub repository: Option<String>,
    /// Expected repository owner for the token
    pub repository_owner: Option<String>,
}

impl GithubJWKS {
    /// Validates a GitHub OIDC token against the provided JSON Web Key Set (JWKS).
    ///
    /// This method performs several checks:
    /// 1. Verifies the token format.
    /// 2. Decodes the token header to find the key ID (kid).
    /// 3. Locates the corresponding key in the JWKS.
    /// 4. Validates the token signature and claims.
    /// 5. Optionally checks the token's audience.
    /// 6. Verifies the token's organization and repository claims against environment variables.
    ///
    /// # Arguments
    ///
    /// * `token` - The GitHub OIDC token to validate.
    /// * `jwks` - An `Arc<RwLock<GithubJWKS>>` containing the JSON Web Key Set.
    /// * `config` - A `GitHubOIDCConfig` struct containing validation options.
    /// * `expected_audience` - An optional expected audience for the token.
    ///
    /// # Returns
    ///
    /// Returns a `Result<GitHubClaims, GitHubOIDCError>` containing the validated claims if successful,
    /// or an error if validation fails.
    ///
    pub fn validate_github_token(
        &self,
        token: &str,
        config: &GitHubOIDCConfig,
    ) -> Result<GitHubClaims, GitHubOIDCError> {
        debug!("Starting token validation");
        if !token.starts_with("eyJ") {
            warn!("Invalid token format received");
            return Err(GitHubOIDCError::InvalidTokenFormat);
        }

        debug!("JWKS loaded");

        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            GitHubOIDCError::HeaderDecodingError(format!(
                "Failed to decode header: {}. Make sure you're using a valid JWT, not a PAT.",
                e
            ))
        })?;

        let decoding_key = if let Some(kid) = header.kid {
            let key = self
                .keys
                .iter()
                .find(|k| k.kid == kid)
                .ok_or(GitHubOIDCError::KeyNotFound)?;

            let modulus = key.n.as_str();
            let exponent = key.e.as_str();

            DecodingKey::from_rsa_components(modulus, exponent)
                .map_err(|e| GitHubOIDCError::DecodingKeyCreationError(e.to_string()))?
        } else {
            DecodingKey::from_secret("your_secret_key".as_ref())
        };

        let mut validation = Validation::new(Algorithm::RS256);
        if let Some(audience) = &config.audience {
            validation.set_audience(&[audience]);
        }

        let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| GitHubOIDCError::TokenDecodingError(e.to_string()))?;

        let claims = token_data.claims;

        if let Some(expected_owner) = &config.repository_owner {
            if claims.repository_owner != *expected_owner {
                warn!(
                    "Token organization mismatch. Expected: {}, Found: {}",
                    expected_owner, claims.repository_owner
                );
                return Err(GitHubOIDCError::OrganizationMismatch);
            }
        }

        if let Some(expected_repo) = &config.repository {
            debug!(
                "Comparing repositories - Expected: {}, Found: {}",
                expected_repo, claims.repository
            );
            if claims.repository != *expected_repo {
                warn!(
                    "Token repository mismatch. Expected: {}, Found: {}",
                    expected_repo, claims.repository
                );
                return Err(GitHubOIDCError::RepositoryMismatch);
            }
        }

        debug!("Token validation completed successfully");
        Ok(claims)
    }
}
