//! Versioned HTTP target admission and reviewed request templates.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use url::Url;

pub const HTTP_POLICY_VERSION: u32 = 1;
pub const MAX_ROUTES: usize = 16;
pub const MAX_FIELDS_PER_ROUTE: usize = 12;
pub const MAX_POLICY_BYTES: u64 = 256 * 1024;
pub const MAX_TIMEOUT_MS: u64 = 5_000;
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
pub const MAX_CALLS: u32 = 32;
pub const MAX_MUTATIONS: u32 = 8;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpEnvironment {
    DisposableFixture,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffect {
    ReadOnly,
    Mutating,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldLimit {
    pub max_utf8_bytes: usize,
}

/// Only low-cardinality scalar observations leave the target adapter. Arbitrary
/// response strings, model-facing text, and nested JSON are deliberately absent.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFieldKind {
    Boolean,
    NonNegativeInteger,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResponseValue {
    Boolean(bool),
    NonNegativeInteger(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    /// Name of an environment variable inspected by the trusted CLI/provider
    /// immediately before execution. Its value is never part of this policy.
    pub environment_variable: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicy {
    pub route_id: String,
    pub method: HttpMethod,
    pub effect: OperationEffect,
    /// Exact, normalized absolute path. No planner-selected URL or path suffix.
    pub path: String,
    pub credential: Option<CredentialRef>,
    /// Required flat query fields. Only valid for GET in this target pack.
    pub query_fields: BTreeMap<String, FieldLimit>,
    /// Required flat JSON string fields. Only valid for POST in this target pack.
    pub body_fields: BTreeMap<String, FieldLimit>,
    /// Reviewed constant headers. Callers cannot replace or extend these.
    pub headers: BTreeMap<String, String>,
    /// Required flat, exact scalar response schema. No arbitrary response text.
    pub response_fields: BTreeMap<String, ResponseFieldKind>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpLimits {
    pub max_calls: u32,
    pub max_mutations: u32,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpTargetPolicy {
    pub schema_version: u32,
    pub target_id: String,
    pub environment: HttpEnvironment,
    /// One normalized http(s) origin. Paths, queries, fragments, and userinfo
    /// are not allowed here. The route is the only source of a request path.
    pub origin: String,
    /// Exact addresses the connection resolver may return. The disposable
    /// fixture target pack admits only loopback addresses.
    pub resolved_addresses: Vec<IpAddr>,
    pub routes: Vec<RoutePolicy>,
    pub limits: HttpLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlannedHttpCall {
    pub route_id: String,
    pub arguments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub base: Url,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpPolicyError(pub String);

impl fmt::Display for HttpPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpPolicyError {}

fn invalid(message: impl Into<String>) -> HttpPolicyError {
    HttpPolicyError(message.into())
}

fn identifier(value: &str, what: &str) -> Result<(), HttpPolicyError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid(format!(
            "{what} is empty, too long, or not a restricted identifier"
        )));
    }
    Ok(())
}

fn header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn fields(
    fields: &BTreeMap<String, FieldLimit>,
    method: HttpMethod,
    query: bool,
) -> Result<(), HttpPolicyError> {
    if fields.len() > MAX_FIELDS_PER_ROUTE {
        return Err(invalid("route has too many request fields"));
    }
    if (method == HttpMethod::GET) != query && !fields.is_empty() {
        return Err(invalid(
            "GET uses query fields and POST uses JSON body fields",
        ));
    }
    for (name, limit) in fields {
        identifier(name, "request field name")?;
        if limit.max_utf8_bytes == 0 || limit.max_utf8_bytes > 2_048 {
            return Err(invalid("request field bound is zero or exceeds 2048 bytes"));
        }
    }
    Ok(())
}

impl RoutePolicy {
    pub fn validate(&self) -> Result<(), HttpPolicyError> {
        identifier(&self.route_id, "route id")?;
        if self.path.is_empty()
            || self.path.len() > 256
            || !self.path.starts_with('/')
            || self.path.contains(['?', '#', '\\', '%'])
            || self.path.split('/').any(|part| matches!(part, "." | ".."))
            || !self.path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
            })
        {
            return Err(invalid(
                "route path is not an exact normalized fixture path",
            ));
        }
        fields(&self.query_fields, self.method, true)?;
        fields(&self.body_fields, self.method, false)?;
        if let Some(credential) = &self.credential {
            let name = &credential.environment_variable;
            if name.is_empty()
                || name.len() > 96
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            {
                return Err(invalid(
                    "credential reference is not a bounded environment name",
                ));
            }
        }
        let mut header_names = BTreeSet::new();
        if self.headers.len() > 16 {
            return Err(invalid("route contains too many static headers"));
        }
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if !header_names.insert(lower.clone())
                || !header_name(name)
                || matches!(
                    lower.as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "host"
                        | "forwarded"
                        | "x-forwarded-for"
                        | "x-forwarded-host"
                        | "connection"
                        | "content-length"
                        | "transfer-encoding"
                )
                || value.len() > 256
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            {
                return Err(invalid(
                    "route contains a forbidden or malformed static header",
                ));
            }
        }
        if self.response_fields.is_empty() || self.response_fields.len() > MAX_FIELDS_PER_ROUTE {
            return Err(invalid("route needs one to twelve scalar response fields"));
        }
        for name in self.response_fields.keys() {
            identifier(name, "response field name")?;
        }
        if !self.body_fields.is_empty()
            && self
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.as_str())
                != Some("application/json")
        {
            return Err(invalid(
                "JSON routes must pin Content-Type: application/json",
            ));
        }
        Ok(())
    }

    pub fn required_fields(&self) -> &BTreeMap<String, FieldLimit> {
        match self.method {
            HttpMethod::GET => &self.query_fields,
            HttpMethod::POST => &self.body_fields,
        }
    }
}

impl HttpTargetPolicy {
    pub fn validate(&self) -> Result<ValidatedOrigin, HttpPolicyError> {
        let origin = self.validated_origin()?;
        identifier(&self.target_id, "target id")?;
        if self.schema_version != HTTP_POLICY_VERSION || self.routes.is_empty() {
            return Err(invalid("unsupported HTTP policy version or missing routes"));
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(invalid("too many HTTP routes"));
        }
        if self.resolved_addresses.is_empty()
            || self.resolved_addresses.len() > 4
            || self
                .resolved_addresses
                .iter()
                .any(|address| !address.is_loopback())
        {
            return Err(invalid(
                "disposable fixtures require one to four exact loopback addresses",
            ));
        }
        let mut ids = BTreeSet::new();
        for route in &self.routes {
            route.validate()?;
            if !ids.insert(route.route_id.clone()) {
                return Err(invalid("duplicate route id"));
            }
        }
        let limits = &self.limits;
        if limits.max_calls == 0
            || limits.max_calls > MAX_CALLS
            || limits.max_mutations > MAX_MUTATIONS
            || limits.max_request_bytes == 0
            || limits.max_request_bytes > MAX_REQUEST_BYTES
            || limits.max_response_bytes == 0
            || limits.max_response_bytes > MAX_RESPONSE_BYTES
            || limits.timeout_ms == 0
            || limits.timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(invalid(
                "HTTP limits are zero or exceed target-pack ceilings",
            ));
        }
        if self
            .routes
            .iter()
            .filter(|route| route.effect == OperationEffect::Mutating)
            .count()
            > limits.max_mutations as usize
        {
            return Err(invalid(
                "mutating route count exceeds the configured effect ceiling",
            ));
        }
        Ok(origin)
    }

    pub fn validated_origin(&self) -> Result<ValidatedOrigin, HttpPolicyError> {
        let base =
            Url::parse(&self.origin).map_err(|_| invalid("HTTP origin is not a valid URL"))?;
        if !matches!(base.scheme(), "http" | "https")
            || !base.username().is_empty()
            || base.password().is_some()
            || base.host_str().is_none()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(invalid(
                "HTTP origin must be one normalized origin without userinfo or path",
            ));
        }
        let host = base
            .host_str()
            .ok_or_else(|| invalid("HTTP origin has no host"))?
            .to_ascii_lowercase();
        if host.is_empty() || host.len() > 253 {
            return Err(invalid("HTTP origin host is empty or too long"));
        }
        let port = base
            .port_or_known_default()
            .ok_or_else(|| invalid("HTTP origin has no effective port"))?;
        Ok(ValidatedOrigin {
            scheme: base.scheme().to_owned(),
            host,
            port,
            base,
        })
    }

    pub fn route(&self, id: &str) -> Option<&RoutePolicy> {
        self.routes.iter().find(|route| route.route_id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HttpTargetPolicy {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        HttpTargetPolicy {
            schema_version: 1,
            target_id: "fixture".into(),
            environment: HttpEnvironment::DisposableFixture,
            origin: "http://127.0.0.1:8080".into(),
            resolved_addresses: vec!["127.0.0.1".parse().unwrap()],
            routes: vec![RoutePolicy {
                route_id: "write".into(),
                method: HttpMethod::POST,
                effect: OperationEffect::Mutating,
                path: "/v1/write".into(),
                credential: Some(CredentialRef {
                    environment_variable: "SMASH_FIXTURE_VIEWER".into(),
                }),
                query_fields: BTreeMap::new(),
                body_fields: BTreeMap::from([(
                    "attempt_id".into(),
                    FieldLimit { max_utf8_bytes: 64 },
                )]),
                headers,
                response_fields: BTreeMap::from([("applied".into(), ResponseFieldKind::Boolean)]),
            }],
            limits: HttpLimits {
                max_calls: 8,
                max_mutations: 2,
                max_request_bytes: 1024,
                max_response_bytes: 4096,
                timeout_ms: 500,
            },
        }
    }

    #[test]
    fn valid_policy_normalizes_origin_and_binds_flat_fields() {
        let origin = policy().validate().unwrap();
        assert_eq!(origin.host, "127.0.0.1");
        assert_eq!(origin.port, 8080);
        assert!(policy().route("write").is_some());
    }

    #[test]
    fn userinfo_ambiguous_paths_reserved_headers_and_non_loopback_are_refused() {
        let mut candidate = policy();
        candidate.origin = "http://viewer@127.0.0.1:8080".into();
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.origin += "/nested";
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.routes[0].path = "/v1/%2e%2e/write".into();
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.routes[0].path = "/v1/../write".into();
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.routes[0]
            .headers
            .insert("X-Forwarded-Host".into(), "elsewhere".into());
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.routes[0]
            .headers
            .insert("content-type".into(), "application/json".into());
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.resolved_addresses = vec!["192.0.2.1".parse().unwrap()];
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn unsupported_methods_bodies_and_unbounded_limits_are_refused() {
        let mut candidate = policy();
        candidate.routes[0].query_fields = candidate.routes[0].body_fields.clone();
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.routes[0].method = HttpMethod::GET;
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.limits.timeout_ms = 60_000;
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.limits.max_response_bytes = MAX_RESPONSE_BYTES + 1;
        assert!(candidate.validate().is_err());
        let mut candidate = policy();
        candidate.schema_version = 2;
        assert!(candidate.validate().is_err());
    }
}
