mod errors;
use errors::GitHubOIDCError;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::future::Future;

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
    /// The subject of the token (e.g the GitHub Actions runner ID).
    pub subject: String,

    /// The full name of the repository.
    pub repository: String,

    /// The owner of the repository.
    pub repository_owner: String,

    /// A reference to the specific job and workflow.
    pub job_workflow_ref: String,

    /// The timestamp when the token was issued.
    pub iat: u64,
}

/// Fetches the JSON Web Key Set (JWKS) from the specified OIDC URL.
///
/// This function is used to retrieve the set of public keys that GitHub uses
/// to sign its JSON Web Tokens (JWTs).
///
/// # Arguments
///
/// * `oidc_url` - The base URL of the OpenID Connect provider (GitHub in this case)
///
/// # Returns
///
/// * `Result<GithubJWKS, GitHubOIDCError>` - A Result containing the fetched JWKS if successful,
///   or an error if the fetch or parsing fails
///
/// # Example
///
/// ```
///
/// let jwks = fetch_jwks(your_oidc_url).await?;
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
    /// * `expected_audience` - An optional expected audience for the token.
    ///
    /// # Returns
    ///
    /// Returns a `Result<GitHubClaims, GitHubOIDCError>` containing the validated claims if successful,
    /// or an error if validation fails.
    ///
    pub async fn validate_github_token(
        &self,
        token: &str,
        expected_audience: Option<&str>,
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
        if let Some(audience) = expected_audience {
            validation.set_audience(&[audience]);
        }

        let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| GitHubOIDCError::TokenDecodingError(e.to_string()))?;

        let claims = token_data.claims;

        if let Ok(org) = std::env::var("GITHUB_ORG") {
            if claims.repository_owner != org {
                warn!(
                    "Token organization mismatch. Expected: {}, Found: {}",
                    org, claims.repository_owner
                );
                return Err(GitHubOIDCError::OrganizationMismatch);
            }
        }

        if let Ok(repo) = std::env::var("GITHUB_REPO") {
            debug!(
                "Comparing repositories - Expected: {}, Found: {}",
                repo, claims.repository
            );
            if claims.repository != repo {
                warn!(
                    "Token repository mismatch. Expected: {}, Found: {}",
                    repo, claims.repository
                );
                return Err(GitHubOIDCError::RepositoryMismatch);
            }
        }

        debug!("Token validation completed successfully");
        Ok(claims)
    }
}

/// Validates a GitHub OIDC token.
///
/// This is a convenience wrapper around `GithubJWKS::validate_github_token`.
/// It provides the same functionality but as a standalone function.
///
/// # Arguments
///
/// * `token` - The GitHub OIDC token to validate.
/// * `jwks` - A reference to `GithubJWKS` containing the JSON Web Key Set.
/// * `expected_audience` - An optional expected audience for the token.
///
/// # Returns
///
/// Returns a `Result<GitHubClaims, GitHubOIDCError>` containing the validated claims if successful,
/// or an error if validation fails.
///
/// # Examples
///
/// ```
/// use github_oidc::{GithubJWKS, validate_github_token, fetch_jwks};
/// use color_eyre::Result;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///
///     match validate_github_token(token, &jwks, Some("https://github.com/your-username")) {
///         Ok(claims) => println!("Token validated successfully. Claims: {:?}", claims),
///         Err(e) => eprintln!("Token validation failed: {}", e),
///     }
///
///     Ok(())
/// }
/// ```
pub fn validate_github_token<'a>(
    token: &'a str,
    jwks: &'a GithubJWKS,
    expected_audience: Option<&'a str>,
) -> impl Future<Output = Result<GitHubClaims, GitHubOIDCError>> + 'a {
    async move {
        jwks.validate_github_token(token, expected_audience).await
    }
}
