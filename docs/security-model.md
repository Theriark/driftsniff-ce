# Security model

Threat-model review of driftsniff CE (P11-T2), written against `development` at commit `0ff6a65bc9a18544254f750def31edcd8efae3f2`. Each control names the test that proves it. A control with no test, or with a known weakness, is in the gap list. Test names were located by reading the test files; the review did not run the suite, so CI on the pull request is the execution evidence.

## What is sensitive

Stored configuration is sensitive even when secret values are redacted. Redaction replaces secret-class values and scanner hits with keyed fingerprints, but everything else in a controller configuration is stored as it was: firewall rules, network and VLAN layout, host and user names, addresses, free text. That history is a map of the network and helps an attacker without a single credential. The scanner only catches secret shapes; a plain value in a free-text field is stored as it is (`test_a_plain_canary_in_a_configuration_text_field_is_not_redacted` documents this). Treat the data volume, every backup of it, the history pages and the API as confidential. The key volume (master key) is needed to read credentials and verify fingerprints; keep it apart from the data volume and from backups.

Assets: source credentials (encrypted), push keys and API tokens (hashed), password hashes, sessions (hashed cookie), master key, configuration history.

Actors: anonymous client; signed-in viewer, operator or admin; API token or push key holder; malicious or compromised monitored controller; page in another origin acting through a signed-in browser; whoever can read a backup or the data volume.

## Controls

### Part 1: Authentication and sessions; API tokens and push keys

Test names are from the repository, located by reading; CI is the evidence.

#### Authentication and sessions (`web/auth.py`, `web/deps.py`; `docs/auth.md`)

| Control | Test |
|---|---|
| argon2id 64 MiB, 3 passes, 1 lane; weaker hash rehashed at sign-in | `test_auth.py::test_the_production_hasher_is_argon2id_with_64_mib_3_passes_and_one_lane`, `test_a_weaker_stored_hash_is_replaced_by_the_current_cost_at_login` |
| Password length 12 to 256 | `test_a_password_under_12_characters_is_refused`, `test_a_password_over_256_characters_is_refused` |
| One generic failure (unknown, wrong password, disabled, locked), equal hashing work | `test_every_failure_gives_the_same_error_and_the_same_hashing_work`, `security/test_authn.py::test_a_wrong_password_and_an_unknown_user_look_the_same` |
| Throttle per user name and per address, doubling wait, 429 with Retry-After | `test_the_sixth_attempt_inside_a_minute_has_to_wait`, `test_every_further_failure_doubles_the_wait`, `test_failures_from_one_address_block_that_address_only`, `test_failures_against_one_user_block_that_user_from_every_address`, `test_the_throttle_table_stays_bounded` |
| 10 failures lock the user for 15 minutes | `test_ten_failures_in_a_row_lock_the_user_for_15_minutes`, `test_a_locked_user_gets_the_generic_error` |
| Cookie of 32 random bytes, only its SHA-256 stored; HttpOnly, SameSite Lax, Secure over HTTPS | `test_login_starts_a_session_and_stores_only_the_hash_of_the_cookie`, `test_a_stolen_database_row_cannot_be_used_as_the_cookie`, `test_web_auth.py::test_login_redirects_and_sets_an_http_only_lax_cookie`, `test_the_cookie_is_secure_when_the_request_came_over_https` |
| New cookie and CSRF value at each sign-in | `test_every_login_gets_its_own_cookie_and_csrf_value` |
| Session ends after 8 h idle, 7 d absolute, on logout, or when the user is disabled | `test_a_session_ends_after_8_hours_without_requests`, `test_a_session_ends_7_days_after_login_even_when_it_is_in_use`, `test_logout_deletes_the_session_row`, `test_a_disabled_user_loses_every_session_at_once` |
| Forged cookie refused | `security/test_authn.py::test_a_forged_or_tampered_session_cookie_is_refused` |
| Setup: one-time code, hash only, single use, 404 once an admin exists, throttled | `test_only_the_hash_of_the_setup_code_is_stored`, `test_a_second_use_of_the_setup_code_fails`, `test_two_requests_with_one_code_make_exactly_one_admin`, `test_web_auth.py::test_the_setup_route_is_404_once_an_admin_exists`, `test_repeated_wrong_setup_codes_give_429` |
| Roles; every route in a table open to exactly its allowed callers | `test_web_auth.py::test_each_route_answers_by_role`, `security/test_route_table.py` (4 tests), `security/test_authn.py::test_no_credential_gets_401_on_every_route_that_needs_one` |
| Last enabled admin cannot be disabled; no self-disable | `test_settings_service.py::test_the_last_enabled_admin_cannot_be_disabled_by_anyone`, `test_an_admin_cannot_disable_their_own_account` |
| Open redirect after sign-in refused | `test_web_preferences.py::test_safe_next_keeps_only_a_local_path`, `test_a_foreign_next_address_goes_to_the_start_page` |

#### API tokens and push keys (`web/bearer.py`, `web/routes_push.py`)

| Control | Test |
|---|---|
| Token of 32 random bytes, shown once, only hash and prefix stored | `test_web_bearer.py::test_a_new_token_has_the_agreed_shape_and_is_shown_once`, `test_only_the_hash_and_the_prefix_are_stored`, `test_a_stolen_database_row_is_not_a_token` |
| Scopes never implied; 401 for a bad token, 403 for a missing scope | `test_scope_matrix`, `security/test_authn.py::test_every_kind_of_bad_token_gets_the_same_answer` |
| Expiry, revocation and a disabled owner stop a token | `test_an_expired_token_gets_401`, `test_a_revoked_token_gets_401_and_revoking_twice_changes_nothing`, `test_the_tokens_of_a_disabled_user_stop_working` |
| Token only in the Authorization header; session cookie never works on the API; a token cannot manage tokens | `security/test_authn.py::test_the_api_token_is_accepted_only_in_the_authorization_header`, `test_a_session_cookie_never_works_on_the_api`, `test_web_bearer.py::test_a_token_cannot_manage_tokens` |
| Refusals audited without the value, rate-limited in the log | `test_creation_use_failure_and_revocation_are_audited_without_the_value`, `test_refusals_of_anonymous_traffic_are_rate_limited_in_the_log`, `test_no_log_line_holds_a_token_value` |
| Push key checked first, in constant time; one 401 for wrong, unknown or non-push | `test_push_endpoint.py::test_a_missing_or_wrong_key_gets_401_and_no_data_is_read`, `test_an_unknown_source_or_one_that_is_not_a_push_source_gets_the_same_401` |
| Push body at most 10 MB; key and body not logged; only declared fields stored | `test_a_body_over_10_mb_gets_413_by_its_declared_length`, `test_a_body_over_10_mb_gets_413_while_it_streams`, `test_the_endpoint_does_not_log_the_key_or_the_body`, `test_undeclared_fields_and_secret_values_are_never_stored` |

### Part 2: CSRF, origin and headers; output encoding; outbound connections and SSRF; secrets handling

#### CSRF, origin and headers (`web/csrf.py`)

| Control | Test |
|---|---|
| Browser writes with a session need the CSRF value, compared in constant time | `test_web_csrf.py::test_a_write_without_the_value_is_refused`, `test_a_write_with_a_wrong_value_is_refused`, `test_the_value_of_another_session_does_not_work`, `test_the_value_is_compared_in_constant_time` |
| Origin, when sent, must equal the base URL; Origin null refused | `test_the_origin_must_be_the_configured_one`, `test_a_form_post_with_the_null_origin_is_still_refused_before_login`, `test_a_foreign_origin_is_refused_before_login_too` |
| Logout needs the value; login and setup keep the origin check only | `test_logout_needs_the_value`, `test_login_and_setup_need_no_value_even_with_a_session` |
| Form read bounded to 16 KB and 64 fields | `test_a_large_form_without_the_value_gets_413`, `test_web_auth.py::test_a_body_over_16_kb_is_refused` |
| CSP, nosniff and Referrer-Policy on every response; no CORS; no-store outside static | `test_every_response_carries_the_security_headers`, `test_the_policy_allows_nothing_inline_and_nothing_foreign`, `test_no_response_has_a_cors_header` |
| API refuses a request carrying the session cookie | `test_the_api_refuses_the_session_cookie`, `test_the_api_refuses_a_cookie_even_without_a_valid_session` |
| Static files cannot escape their folder | `test_routes_static.py::test_anything_outside_the_folder_or_missing_is_404`, `test_resolve_static_refuses_escapes_and_accepts_files` |

#### Output encoding

| Control | Test |
|---|---|
| No unsafe template marker; no autoescape off | `security/test_template_scan.py::test_no_template_uses_an_unsafe_marker`, `test_no_code_builds_a_template_environment_with_autoescape_off` |
| Hostile input comes back inert | `security/test_xss.py::test_payloads_come_back_unchanged_as_inert_json`, `test_no_route_answers_with_a_page` |

#### Outbound connections and SSRF (`sources/addresses.py`, `collectors/`, `notify/`)

Policy: private and loopback targets are allowed on purpose. Link-local `169.254.0.0/16`, `fe80::/10` and `100.100.100.200` are always refused, also in other IPv4 spellings and inside IPv4-mapped, NAT64, IPv4-compatible and 6to4 IPv6. Sources and webhooks are admin-managed.

| Control | Test |
|---|---|
| Blocked ranges refused whatever the options; plain http needs an option; no credentials in the address | `test_source_addresses.py::test_a_blocked_address_is_refused`, `test_allow_plain_http_never_unblocks_an_address`, `test_plain_http_needs_the_option`, `test_malformed_addresses_are_refused` |
| Embedded IPv4 judged by the inner address | `test_source_addresses_embedded.py` (13 tests) |
| Redirects never followed | `test_redirects_are_never_followed`, `test_notify_webhook.py::test_a_redirect_to_the_metadata_address_is_a_failure_and_nothing_follows_it` |
| Webhook and mail connect to the checked address (rebinding closed) | `test_the_connection_goes_to_the_address_that_was_checked_not_to_the_name`, `test_a_name_that_resolves_to_a_blocked_address_is_refused`, `test_one_blocked_answer_among_allowed_ones_refuses_the_target` |
| UniFi and Xen Orchestra connect to the checked address (rebinding closed): the name is resolved once in `probe()`, the first answer is pinned, a later answer is never used, the TLS host name check and SNI keep the name | `contract/test_collector_pinning.py::test_unifi_connects_to_the_first_answer_and_never_uses_a_later_one`, `test_xo_connects_to_the_first_answer_and_never_uses_a_later_one`, `test_a_blocked_answer_sends_nothing_to_either_collector`, `test_ca_file_mode_refuses_a_name_the_certificate_does_not_cover` |
| Webhook signed over timestamp and body | `test_the_signature_covers_the_timestamp_and_the_body_with_the_documented_construction` |
| TLS verified by default; `ca_file`, pinned and insecure are explicit; a pin mismatch sends nothing | `contract/test_tls.py` |
| Probe never prints the credential | `test_source_probe.py` |

Collector rebinding is closed for UniFi and Xen Orchestra (gap G1, fixed).

#### Secrets handling (`secrets/`)

| Control | Test |
|---|---|
| AES-256-GCM bound to source id and key id | `test_crypto.py::test_a_credential_moved_to_another_source_fails`, `test_a_flipped_bit_fails`, `test_the_plaintext_does_not_appear_in_the_stored_value` |
| Master key mode 0400 or 0600, atomic, never overwritten, start refused if lost while fingerprints exist, links refused | `test_keys.py` (`test_a_key_file_with_any_other_mode_is_refused_and_kept`, `test_missing_key_with_fingerprints_is_refused_and_not_created`, `test_a_symbolic_link_to_a_real_key_is_refused`, `test_an_existing_key_is_loaded_and_never_overwritten`) |
| Secrets stored as keyed, domain-separated fingerprints | `test_redact.py`, `test_fingerprint.py::test_the_same_value_in_two_fields_gives_two_fingerprints` |
| Scanner rules (PEM, JWT, URL credentials, prefixes, entropy) | `test_scanner.py` |
| Canary harness finds secrets in the database, logs, errors, and compressed and base64 forms | `security/test_canary_leaks.py` (16 tests) and per-surface canary tests |
| Log filter scrubs secret shapes and query strings | `test_log_filter.py` |
| No password, cookie or setup code in logs | `test_web_auth.py::test_no_password_or_cookie_value_reaches_the_logs` |
| Push key hashed, credential encrypted | `test_canary_leaks.py::test_the_source_credential_is_encrypted_and_the_push_key_is_hashed` |

### Part 3: Container and deployment; supply chain; backups and data handling

#### Container and deployment

| Control | Test or check |
|---|---|
| Non-root uid 10001, read-only root, `cap_drop` ALL, no-new-privileges, memory limit, port on 127.0.0.1 | `scripts/container-smoke.sh` (CI Container smoke); compose validated in Build image |
| No credential-like ARG or ENV | `test_check_dockerfile_credentials.py::test_shipped_dockerfile_has_no_credential_names` |
| Access log and server header off; data directory 0700 | `cli.py`; no test found (gap G8) |

#### Supply chain

| Control | Test or check |
|---|---|
| Hash-locked requirements, `--require-hashes`, no index | `test_check_lock_hashes.py`; Dockerfile |
| pip-audit; Trivy HIGH/CRITICAL with a fix; licence allow list | CI Dependency audit, Image scan, Licences (`test_check_licenses.py`) |
| gitleaks on files and pull request commits | CI Secret scan (gap G4) |
| Actions pinned by SHA; SBOM; one image built, scanned, smoked, then pushed | CI Build image, SBOM; `docs/ci-baseline.md` |

#### Backups and data handling

| Control | Test |
|---|---|
| Consistent copy, integrity-checked, mode 0600, never overwrites or follows a link, removed on failure, key-volume warning | `test_backup.py::test_the_backup_is_a_checked_single_file_with_the_data_of_the_original`, `test_a_backup_never_overwrites_an_existing_file`, `test_a_backup_never_follows_a_link_at_the_target`, `test_a_copy_that_fails_its_integrity_check_is_removed`, `test_the_command_writes_the_file_and_warns_about_the_key_volume` |
| Retention pruning | `test_retention.py` |
| Audit events without secret values | `test_settings_service.py::test_an_added_user_is_listed_without_a_hash_and_audited_with_the_admin_as_actor`, `test_each_retention_change_writes_one_audit_event_with_old_and_new` |

## Gaps and review notes

No high finding is open. These gaps are listed here and are not fixed by this document.

| Id | Severity | Gap | Fix |
|---|---|---|---|
| G1 | Medium | **Fixed.** Xen Orchestra and UniFi clients resolved a name once, checked the answers, then connected by name (DNS rebinding window). Now `probe()` resolves once (`collectors/resolve.py::pin_address`), refuses a blocked answer and pins the first answer; every connection of the run goes to that address (`collectors/tls.py::AddressPin`, `AddressBackend`) in all four TLS modes, while the name stays the TLS host name, SNI and `Host`. A new probe is a new lookup; with no pinned address a connection fails closed. | Test: `contract/test_collector_pinning.py::test_unifi_connects_to_the_first_answer_and_never_uses_a_later_one` and `test_xo_connects_to_the_first_answer_and_never_uses_a_later_one` (a name that does not exist in DNS; the second answer is the metadata address and is never used). |
| G2 | Low | With `DRIFTSNIFF_TRUSTED_PROXY=true` uvicorn uses `forwarded_allow_ips=*` (`cli.py`). If the port is reachable by anything but the proxy, `X-Forwarded-For` (resets the per-address throttle; per-user throttle and lock remain) and `X-Forwarded-Proto` are forgeable. Default compose binds 127.0.0.1, trusted proxy off. No test. | Proxy list from a setting; document that the port must not be exposed. |
| G3 | Low | Anyone knowing a user name can lock that user for 15 minutes, including the only admin. Throttle is in memory, single worker, 4096 keys (eviction possible; stored lock unaffected). | Accept for CE and document; optional CLI unlock. |
| G4 | Low | gitleaks runs only in CI: no documented local command or pre-commit config; commit scan only on pull requests, a push to `development` scans files only. `.gitleaksignore` has three exact-commit entries for synthetic fixtures with reasons; reviewed, acceptable. | Document a local command or pre-commit config; scan pushed commits. |
| G5 | Low | The first-run setup code is printed once to stdout, so it lands in container logs. By design; single use. | Document that first-start logs are sensitive until setup is done. |
| G6 | Low | Member hash: anonymous set members are ordered by an unsalted SHA-256 of canonical content (`core/normalize.py::_set_sort_key`). After redaction it is a sort key only; the shown label comes from a keyed fingerprint (`core/order.py`). Not stored or shown today; if it were, a low-entropy member could be guessed. | Keep it a sort key; add a test that fails if the digest is stored or rendered. |
| G7 | Low | The last-admin guard sits only in the disable path, the only way an admin can be removed today (no role-change or delete route). A future such route would bypass it with no test to notice. | Call the same guard in any new route; add a service test. |
| G8 | Low | No HSTS or Permissions-Policy. The cookie is Secure only when the app sees HTTPS: behind a TLS proxy without `TRUSTED_PROXY=true` it is not. Access log off and data directory 0700 are untested. | Document the proxy requirement; consider HSTS for an https base URL; add the two tests. |
| G9 | Low | Dependabot covers GitHub Actions only; Python requirements and the base image `python:3.12-slim-bookworm` (tag, not digest) have no update automation; SBOM not signed or attested. | Add pip and docker ecosystems; pin the base by digest. |
| G10 | Low | Backups hold the full configuration history and encrypted credentials; no automated test restores a backup and starts from it. | Add a restore test; document backup storage. |
| G11 | Info | The scanner is a safety net: non-secret-shaped values in free text are stored as they are. | Covered by the sensitivity statement. |

An independent pass by the Application Security Engineer can be requested by Delivery; G2 deserves it; the G1 change is to be reviewed once CI is green.
