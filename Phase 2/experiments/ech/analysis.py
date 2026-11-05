"""Join endpoint evidence to passive observations, then compare feature groups."""

from collections import Counter, defaultdict


def endpoint_key(row):
    return (row["client_ip"], row["client_port"], row["server_ip"],
            row["server_port"], row["outer_random"])


def passive_key(row):
    side = row.get("client_endpoint")
    if side not in ("a", "b"):
        return None
    client = row[f"endpoint_{side}"]
    server = row["endpoint_b" if side == "a" else "endpoint_a"]
    return (client["ip"], client["port"], server["ip"], server["port"],
            row["client"].get("outer_random"))


def index_rows(rows, key):
    result = defaultdict(list)
    for row in rows:
        result[key(row)].append(row)
    return result


def evidence_errors(client, server, passive, mode, profile):
    """A label requires observed endpoint behavior and a complete passive join."""
    errors = []
    if client.get("role") != "client" or server.get("role") != "server":
        errors.append("endpoint_role_conflict")
    if client.get("session") != server.get("session"):
        errors.append("endpoint_session_conflict")
    if not client.get("config_sha256") or client.get("config_sha256") != server.get("config_sha256"):
        errors.append("endpoint_configuration_conflict")
    for role, row in (("client", client), ("server", server)):
        if not row.get("handshake_success"):
            errors.append(f"{role}_handshake_failed")
        if row.get("version") != 772 or row.get("alpn") != "h2":
            errors.append(f"{role}_unexpected_negotiation")
        if row.get("group") != {"A": 29, "B": 23}[profile]:
            errors.append(f"{role}_unexpected_group")
        if row.get("hrr") or row.get("resumed") or row.get("outer_count") != 1:
            errors.append(f"{role}_unexpected_handshake_path")
    if not client.get("certificate_verified"):
        errors.append("certificate_not_verified")
    if not passive.get("complete_hello_pair"):
        errors.append("incomplete_passive_pair")
    if passive["server"].get("negotiated_version") != 772:
        errors.append("passive_version_mismatch")
    if passive.get("limitations") or any(item.get("issues") for item in passive.get("transport", [])):
        errors.append("passive_limit_or_transport_issue")
    hello = passive["client"]
    if hello.get("outer_sni") != "public.ech.test" or hello.get("alpn") != "h2":
        errors.append("unexpected_outer_parameters")
    ech = hello["ech"]
    bodies = ech.get("occurrences", [])
    if (ech.get("presence") is not True or ech.get("findings") or len(bodies) != 1
            or bodies[0].get("status") != "complete" or bodies[0].get("variant") != 0):
        errors.append("invalid_ech_observation")
    if not hello.get("ja3") or not hello.get("ja4"):
        errors.append("missing_fingerprint")
    if mode == "accepted":
        if not client.get("config_installed") or client.get("ech_grease_enabled"):
            errors.append("real_configuration_not_established")
        if not all(row.get("accepted") and row.get("inner_count") == 1 for row in (client, server)):
            errors.append("acceptance_not_confirmed")
        if len(bodies) == 1 and tuple(bodies[0].get(field) for field in
                                     ("kdf_id", "aead_id", "config_id", "enc_length")) != (1, 1, 42, 32):
            errors.append("unexpected_real_ech_configuration")
    elif mode == "grease":
        if client.get("config_installed") or not client.get("ech_grease_enabled"):
            errors.append("grease_controls_not_established")
        if any(row.get("accepted") or row.get("inner_count") != 0 for row in (client, server)):
            errors.append("grease_endpoint_conflict")
    else:
        errors.append("unknown_mode")
    return errors


def join_session(session, schedule, attempts, clients, servers, passive):
    """Never choose arbitrarily between duplicate records or lose unmatched rows."""
    attempt_index = index_rows(attempts, lambda row: row["attempt_id"])
    client_index = index_rows(clients, lambda row: row["attempt_id"])
    client_connections = index_rows(clients, endpoint_key)
    server_index = index_rows(servers, endpoint_key)
    passive_index = index_rows(passive, passive_key)
    schedule_counts = Counter(row["attempt_id"] for row in schedule)
    seen_clients, seen_servers, seen_passive = set(), set(), set()
    joined = []
    for spec in schedule:
        row = {"session": session, **spec, "eligible": False, "label": "unknown"}
        errors = []
        aid = spec["attempt_id"]
        if schedule_counts[aid] != 1:
            errors.append("duplicate_scheduled_attempt")
        seen_clients.add(aid)
        client_rows = client_index.get(aid, [])
        attempt_rows = attempt_index.get(aid, [])
        if len(attempt_rows) != 1 or attempt_rows[0].get("returncode") != 0:
            errors.append("attempt_missing_duplicate_or_failed")
        if len(client_rows) != 1:
            errors.append("client_missing_or_duplicate")
        else:
            client = client_rows[0]
            key = endpoint_key(client)
            if (len(client_connections[key]) != 1 or client.get("session") != session
                    or client.get("profile") != spec["profile"]):
                errors.append("client_identity_conflict")
            if len(key[4]) != 64 or any(ch not in "0123456789abcdef" for ch in key[4]):
                errors.append("invalid_outer_random")
            row.update(client_port=key[1], server_port=key[3], outer_random=key[4])
            seen_servers.add(key)
            seen_passive.add(key)
            server_rows, passive_rows = server_index.get(key, []), passive_index.get(key, [])
            if len(server_rows) != 1:
                errors.append("server_missing_or_duplicate")
            if len(passive_rows) != 1:
                errors.append("passive_missing_or_duplicate")
            if len(server_rows) == len(passive_rows) == 1:
                observation = passive_rows[0]
                errors.extend(evidence_errors(client, server_rows[0], observation, spec["mode"], spec["profile"]))
                hello = observation["client"]
                row.update(ja3=hello.get("ja3"), ja4=hello.get("ja4"))
                bodies = hello["ech"].get("occurrences", [])
                if len(bodies) == 1:
                    row.update({field: bodies[0].get(field) for field in
                                ("kdf_id", "aead_id", "enc_length", "ciphertext_length")})
        row["errors"] = errors
        row["eligible"] = not errors
        if not errors:
            row["label"] = "accepted_real" if spec["mode"] == "accepted" else "grease"
        joined.append(row)
    anomalies = []
    for source, index, seen in (("client", client_index, seen_clients),
                                 ("server", server_index, seen_servers),
                                 ("passive", passive_index, seen_passive)):
        for key, rows in index.items():
            if key not in seen:
                anomalies.append({"source": source, "reason": "unmatched", "key": key, "records": rows})
            elif len(rows) > 1:
                anomalies.append({"source": source, "reason": "duplicate", "key": key, "records": rows})
    scheduled = {row["attempt_id"] for row in schedule}
    for aid, rows in attempt_index.items():
        if aid not in scheduled or len(rows) > 1:
            anomalies.append({"source": "attempt", "key": aid, "records": rows})
    return joined, anomalies


def feature_key(row, kind, augmented):
    values = (row[kind],)
    if augmented:
        values += tuple(row[field] for field in ("kdf_id", "aead_id", "enc_length", "ciphertext_length"))
    return values


def compare(rows):
    """Descriptive grouping only. Session labels never enter fingerprint inputs."""
    measurements = []
    groups_export = []
    for kind in ("ja3", "ja4"):
        for augmented in (False, True):
            name = kind + ("_augmented" if augmented else "")
            groups = defaultdict(list)
            for row in rows:
                groups[feature_key(row, kind, augmented)].append(row)
            shared = {key for key, members in groups.items() if len({row["profile"] for row in members}) > 1}
            item = {"features": name, "distinct_groups": len(groups), "shared_groups": len(shared),
                    "shared_observation_fraction": sum(len(groups[key]) for key in shared) / len(rows) if rows else None,
                    "profiles": {}}
            for profile in ("A", "B"):
                subset = [row for row in rows if row["profile"] == profile]
                counts = Counter(feature_key(row, kind, augmented) for row in subset)
                sessions = {}
                sets = []
                for session in sorted({row["session"] for row in subset}):
                    values = {feature_key(row, kind, augmented) for row in subset if row["session"] == session}
                    sessions[session] = len(values)
                    sets.append(values)
                item["profiles"][profile] = {
                    "observations": len(subset), "distinct": len(counts),
                    "modal_share": max(counts.values()) / len(subset) if subset else None,
                    "distinct_per_session": sessions,
                    "groups_present_in_every_session": len(set.intersection(*sets)) if sets else 0,
                }
            for key, members in sorted(groups.items()):
                groups_export.append({"features": name, "key": key,
                                      "profiles": dict(Counter(row["profile"] for row in members)),
                                      "sessions": dict(Counter(row["session"] for row in members))})
            measurements.append(item)
    return measurements, groups_export
