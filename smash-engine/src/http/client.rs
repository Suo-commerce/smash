//! Controlled M3 execution over ureq's real resolver/connection path.

use crate::canonical::parse_no_duplicates;
use crate::http::policy::{
    HttpMethod, HttpPolicyError, HttpTargetPolicy, OperationEffect, PlannedHttpCall, RoutePolicy,
    ValidatedOrigin,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::error::Error as _;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpDisposition {
    NotDispatched,
    Resolved,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseFailure {
    pub reason: String,
}

pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_sha256: String,
    pub body_length: u64,
    body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_sha256", &self.body_sha256)
            .field("body_length", &self.body_length)
            .field("body", &"<not exposed in Debug>")
            .finish()
    }
}

impl HttpResponse {
    /// Parse only inside the target adapter. Raw response text is not put into
    /// transport errors, ordinary evidence, or planner contracts.
    pub fn parse_json(&self) -> Result<Value, ResponseFailure> {
        parse_no_duplicates(&self.body).map_err(|_| ResponseFailure {
            reason: "response body is not strict JSON".into(),
        })
    }
}

#[derive(Debug)]
pub enum WireOutcome {
    /// Policy or admission refused before a connection was made.
    Denied(ResponseFailure),
    /// A dispatched response could not be interpreted within the contract.
    Malformed(ResponseFailure),
    /// Valid protocol/transport behavior that this target pack does not handle.
    Unhandled {
        failure: ResponseFailure,
        unresolved: bool,
    },
    /// Deadline elapsed. A dispatched operation may have had an effect.
    Timeout,
    /// A bounded response is available to the target-owned adapter/oracle.
    Observed(HttpResponse),
}

#[derive(Debug)]
pub struct HttpExchange {
    pub outcome: WireOutcome,
}

impl HttpExchange {
    pub fn disposition(&self) -> HttpDisposition {
        match &self.outcome {
            WireOutcome::Denied(_) => HttpDisposition::NotDispatched,
            WireOutcome::Timeout
            | WireOutcome::Unhandled {
                unresolved: true, ..
            } => HttpDisposition::Unresolved,
            WireOutcome::Malformed(_)
            | WireOutcome::Unhandled {
                unresolved: false, ..
            }
            | WireOutcome::Observed(_) => HttpDisposition::Resolved,
        }
    }
}

fn denied(reason: impl Into<String>) -> HttpExchange {
    HttpExchange {
        outcome: WireOutcome::Denied(ResponseFailure {
            reason: reason.into(),
        }),
    }
}

fn transport_timed_out(error: &ureq::Transport) -> bool {
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        }) {
            return true;
        }
        source = cause.source();
    }
    false
}

fn malformed(reason: impl Into<String>) -> HttpExchange {
    HttpExchange {
        outcome: WireOutcome::Malformed(ResponseFailure {
            reason: reason.into(),
        }),
    }
}

fn unhandled(reason: impl Into<String>, unresolved: bool) -> HttpExchange {
    HttpExchange {
        outcome: WireOutcome::Unhandled {
            failure: ResponseFailure {
                reason: reason.into(),
            },
            unresolved,
        },
    }
}

type PreparedRequest = (Url, Option<Vec<u8>>, Option<String>);

struct BoundResolver {
    host: String,
    port: u16,
    allowed: Vec<IpAddr>,
    denied: Arc<AtomicBool>,
}

impl BoundResolver {
    fn authority_matches(&self, netloc: &str) -> bool {
        let Some((host, port)) = netloc.rsplit_once(':') else {
            return false;
        };
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        host.eq_ignore_ascii_case(&self.host)
            && port
                .parse::<u16>()
                .map(|port| port == self.port)
                .unwrap_or(false)
    }
}

impl ureq::Resolver for BoundResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let resolved = if self.authority_matches(netloc) {
            netloc.to_socket_addrs()?.collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let admitted: Vec<_> = resolved
            .into_iter()
            .filter(|address| address.port() == self.port && self.allowed.contains(&address.ip()))
            .collect();
        if admitted.is_empty() {
            self.denied.store(true, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "M3 connection resolver denied every destination",
            ));
        }
        Ok(admitted)
    }
}

/// One controlled HTTP client for an admitted target. Serial target-pack
/// campaigns own it; its Cell counters are deliberately not a concurrency API.
pub struct HttpClient {
    policy: HttpTargetPolicy,
    origin: ValidatedOrigin,
    agent: ureq::Agent,
    resolver_denied: Arc<AtomicBool>,
    calls: Cell<u32>,
    mutations: Cell<u32>,
}

impl HttpClient {
    pub fn new(policy: &HttpTargetPolicy) -> Result<Self, HttpPolicyError> {
        let origin = policy.validate()?;
        let timeout = Duration::from_millis(policy.limits.timeout_ms);
        let resolver_denied = Arc::new(AtomicBool::new(false));
        let resolver = BoundResolver {
            host: origin.host.clone(),
            port: origin.port,
            allowed: policy.resolved_addresses.clone(),
            denied: Arc::clone(&resolver_denied),
        };
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .try_proxy_from_env(false)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .timeout(timeout)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .resolver(resolver)
            // ureq's default TLS configuration verifies certificates. No M3
            // constructor accepts a verification bypass or ambient proxy.
            .build();
        Ok(Self {
            policy: policy.clone(),
            origin,
            agent,
            resolver_denied,
            calls: Cell::new(0),
            mutations: Cell::new(0),
        })
    }

    fn prepare(
        &self,
        route: &RoutePolicy,
        call: &PlannedHttpCall,
        credential: Option<&str>,
    ) -> Result<PreparedRequest, String> {
        let fields = route.required_fields();
        if call.arguments.len() != fields.len()
            || call.arguments.keys().any(|name| !fields.contains_key(name))
        {
            return Err("planned call does not exactly match reviewed request fields".into());
        }
        for (name, value) in &call.arguments {
            let limit = fields
                .get(name)
                .ok_or_else(|| "field admission failed".to_owned())?;
            if value.is_empty() || value.len() > limit.max_utf8_bytes {
                return Err("planned call field is empty or exceeds its bound".into());
            }
        }
        let mut url = self.origin.base.clone();
        url.set_path(&route.path);
        url.set_query(None);
        url.set_fragment(None);
        let body = match route.method {
            HttpMethod::GET => {
                {
                    let mut query = url.query_pairs_mut();
                    for (name, value) in &call.arguments {
                        query.append_pair(name, value);
                    }
                }
                None
            }
            HttpMethod::POST => {
                let body = serde_json::to_vec(&call.arguments)
                    .map_err(|_| "JSON body serialization failed".to_owned())?;
                Some(body)
            }
        };
        let credential = match (&route.credential, credential) {
            (None, None) => None,
            (Some(_), Some(secret))
                if !secret.is_empty()
                    && secret.len() <= 4_096
                    && !secret.contains(['\r', '\n']) =>
            {
                Some(format!("Bearer {secret}"))
            }
            (Some(_), _) => {
                return Err("required execution credential is absent or malformed".into())
            }
            (None, Some(_)) => return Err("credential supplied to an unauthenticated route".into()),
        };
        let static_bytes: usize = route
            .headers
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum();
        let request_bytes = url.as_str().len()
            + static_bytes
            + body.as_ref().map_or(0, Vec::len)
            + credential.as_ref().map_or(0, |value| value.len() + 30);
        if request_bytes as u64 > self.policy.limits.max_request_bytes {
            return Err("prepared request exceeds its byte ceiling".into());
        }
        Ok((url, body, credential))
    }

    pub fn dispatch(&self, call: &PlannedHttpCall, credential: Option<&str>) -> HttpExchange {
        let Some(route) = self.policy.route(&call.route_id) else {
            return denied("route is not admitted");
        };
        let (url, body, secret_header) = match self.prepare(route, call, credential) {
            Ok(prepared) => prepared,
            Err(reason) => return denied(reason),
        };
        if self.calls.get() >= self.policy.limits.max_calls {
            return denied("HTTP call budget exhausted");
        }
        if route.effect == OperationEffect::Mutating
            && self.mutations.get() >= self.policy.limits.max_mutations
        {
            return denied("mutating-call budget exhausted");
        }
        self.calls.set(self.calls.get() + 1);
        if route.effect == OperationEffect::Mutating {
            self.mutations.set(self.mutations.get() + 1);
        }

        self.resolver_denied.store(false, Ordering::SeqCst);
        let mut request = match route.method {
            HttpMethod::GET => self.agent.get(url.as_str()),
            HttpMethod::POST => self.agent.post(url.as_str()),
        };
        for (name, value) in &route.headers {
            request = request.set(name, value);
        }
        if let Some(secret) = &secret_header {
            // The secret is applied only after plan/template validation and is
            // absent from response records and every local error string.
            request = request.set("Authorization", secret);
        }
        let started = std::time::Instant::now();
        let result = match route.method {
            HttpMethod::GET => request.call(),
            HttpMethod::POST => request.send_bytes(body.as_deref().unwrap_or_default()),
        };
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => {
                if self.resolver_denied.load(Ordering::SeqCst) {
                    return denied("connection resolver denied the actual destination");
                }
                if transport_timed_out(&error) {
                    return HttpExchange {
                        outcome: WireOutcome::Timeout,
                    };
                }
                return if error.kind() == ureq::ErrorKind::InvalidUrl {
                    malformed("HTTP client rejected the URL")
                } else {
                    unhandled("HTTP transport failed; effect may be unresolved", true)
                };
            }
        };
        if (300..400).contains(&response.status()) {
            // Redirect following is disabled even within one origin. Location
            // is not evaluated, executed, logged, or persisted as trusted data.
            return unhandled("redirect response refused without following", false);
        }
        let status = response.status();
        let content_type = response
            .header("content-type")
            .filter(|value| value.len() <= 128 && !value.contains(['\r', '\n']))
            .map(str::to_owned);
        let mut response_bytes = Vec::new();
        let read_result = response
            .into_reader()
            .take(self.policy.limits.max_response_bytes + 1)
            .read_to_end(&mut response_bytes);
        if let Err(error) = read_result {
            return if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                HttpExchange {
                    outcome: WireOutcome::Timeout,
                }
            } else {
                unhandled("response read failed; effect may be unresolved", true)
            };
        }
        if response_bytes.len() as u64 > self.policy.limits.max_response_bytes {
            return malformed("response body exceeds its byte ceiling");
        }
        if started.elapsed() >= Duration::from_millis(self.policy.limits.timeout_ms) {
            return HttpExchange {
                outcome: WireOutcome::Timeout,
            };
        }
        let body_sha256 = format!("{:x}", Sha256::digest(&response_bytes));
        HttpExchange {
            outcome: WireOutcome::Observed(HttpResponse {
                status,
                content_type,
                body_sha256,
                body_length: response_bytes.len() as u64,
                body: response_bytes,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::policy::{
        CredentialRef, FieldLimit, HttpEnvironment, HttpLimits, ResponseFieldKind, RoutePolicy,
        HTTP_POLICY_VERSION,
    };
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    fn route(id: &str, method: HttpMethod, path: &str) -> RoutePolicy {
        let mut fields = BTreeMap::new();
        fields.insert("attempt_id".into(), FieldLimit { max_utf8_bytes: 96 });
        RoutePolicy {
            route_id: id.into(),
            method,
            effect: if method == HttpMethod::POST {
                OperationEffect::Mutating
            } else {
                OperationEffect::ReadOnly
            },
            path: path.into(),
            credential: Some(CredentialRef {
                environment_variable: "SMASH_M3_TEST_SECRET".into(),
            }),
            query_fields: if method == HttpMethod::GET {
                fields.clone()
            } else {
                BTreeMap::new()
            },
            body_fields: if method == HttpMethod::POST {
                fields
            } else {
                BTreeMap::new()
            },
            headers: if method == HttpMethod::POST {
                BTreeMap::from([("Content-Type".into(), "application/json".into())])
            } else {
                BTreeMap::new()
            },
            response_fields: BTreeMap::from([("ok".into(), ResponseFieldKind::Boolean)]),
        }
    }

    fn policy_for(listener: &TcpListener, routes: Vec<RoutePolicy>) -> HttpTargetPolicy {
        let address = listener.local_addr().unwrap();
        HttpTargetPolicy {
            schema_version: HTTP_POLICY_VERSION,
            target_id: "test-fixture".into(),
            environment: HttpEnvironment::DisposableFixture,
            origin: format!("http://{address}"),
            resolved_addresses: vec![address.ip()],
            routes,
            limits: HttpLimits {
                max_calls: 12,
                max_mutations: 4,
                max_request_bytes: 4_096,
                max_response_bytes: 128,
                timeout_ms: 150,
            },
        }
    }

    fn call(route: &str) -> PlannedHttpCall {
        PlannedHttpCall {
            route_id: route.into(),
            arguments: BTreeMap::from([("attempt_id".into(), "attempt-1".into())]),
        }
    }

    fn respond(listener: TcpListener, response: &'static [u8]) -> thread::JoinHandle<String> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut input = [0_u8; 4_096];
            loop {
                let count = stream.read(&mut input).unwrap();
                assert!(count > 0, "client closed an incomplete request");
                request.extend_from_slice(&input[..count]);
                let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4)
                else {
                    continue;
                };
                let content_length = String::from_utf8_lossy(&request[..header_end])
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            let seen = String::from_utf8_lossy(&request).into_owned();
            stream.write_all(response).unwrap();
            seen
        })
    }

    #[test]
    fn authorized_request_injects_credentials_only_at_execution() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(
            &listener,
            vec![route("write", HttpMethod::POST, "/v1/write")],
        );
        let server = respond(
            listener,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}",
        );
        let client = HttpClient::new(&policy).unwrap();
        let exchange = client.dispatch(&call("write"), Some("test-secret-value"));
        let WireOutcome::Observed(response) = &exchange.outcome else {
            panic!("expected observation: {:?}", exchange.outcome);
        };
        assert_eq!(response.status, 200);
        assert_eq!(response.parse_json().unwrap()["status"], "ok");
        assert!(!format!("{response:?}").contains("test-secret-value"));
        let request = server.join().unwrap();
        assert!(request.contains("Authorization: Bearer test-secret-value"));
        assert!(request.contains("/v1/write"));
        assert!(request.contains("attempt-1"));
    }

    #[test]
    fn missing_credentials_bad_plans_and_budgets_never_open_a_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        let client = HttpClient::new(&policy).unwrap();
        assert!(matches!(
            client.dispatch(&call("read"), None).outcome,
            WireOutcome::Denied(_)
        ));
        assert!(matches!(
            client.dispatch(&call("missing"), Some("secret")).outcome,
            WireOutcome::Denied(_)
        ));
        let mut wrong = call("read");
        wrong
            .arguments
            .insert("extra".into(), "not-admitted".into());
        assert!(matches!(
            client.dispatch(&wrong, Some("secret")).outcome,
            WireOutcome::Denied(_)
        ));
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        assert!(
            listener.accept().is_err(),
            "no connection should be attempted"
        );
    }

    #[test]
    fn resolver_filters_the_actual_connection_addresses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        policy.resolved_addresses = vec!["127.0.0.2".parse().unwrap()];
        let client = HttpClient::new(&policy).unwrap();
        assert!(matches!(
            client.dispatch(&call("read"), Some("secret")).outcome,
            WireOutcome::Denied(_)
        ));
        listener.set_nonblocking(true).unwrap();
        assert!(
            listener.accept().is_err(),
            "mismatch must deny before connect"
        );
    }

    #[test]
    fn redirects_timeouts_and_oversized_bodies_are_bounded_non_observations() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        let server = respond(
            listener,
            b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let client = HttpClient::new(&policy).unwrap();
        assert!(matches!(
            client.dispatch(&call("read"), Some("secret")).outcome,
            WireOutcome::Unhandled { .. }
        ));
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(300));
        });
        let client = HttpClient::new(&policy).unwrap();
        let exchange = client.dispatch(&call("read"), Some("secret"));
        assert!(matches!(exchange.outcome, WireOutcome::Timeout));
        assert_eq!(exchange.disposition(), HttpDisposition::Unresolved);
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        let server = respond(
            listener,
            b"HTTP/1.1 200 OK\r\nContent-Length: 129\r\nConnection: close\r\n\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let client = HttpClient::new(&policy).unwrap();
        assert!(matches!(
            client.dispatch(&call("read"), Some("secret")).outcome,
            WireOutcome::Malformed(_)
        ));
        server.join().unwrap();
    }

    #[test]
    fn invalid_utf8_and_invalid_json_do_not_reach_the_oracle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy_for(&listener, vec![route("read", HttpMethod::GET, "/v1/read")]);
        let server = respond(
            listener,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\xff",
        );
        let client = HttpClient::new(&policy).unwrap();
        let WireOutcome::Observed(response) =
            &client.dispatch(&call("read"), Some("secret")).outcome
        else {
            panic!("transport should retain bytes for strict target interpretation");
        };
        assert!(response.parse_json().is_err());
        server.join().unwrap();
    }
}
