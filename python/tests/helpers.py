"""Find an agent's chain in the (project, env, agent) layout."""


def chain_of(rec, agent="claims-project"):
    found = [c for c in rec.state.chains() if c.rsplit("/", 1)[1] == agent]
    assert len(found) == 1, found
    return found[0]


def records(rec, agent="claims-project"):
    return list(rec.state.read_all(chain_of(rec, agent)))


def chain_path(rec, agent="claims-project"):
    return rec.state.chain_path(chain_of(rec, agent))


def error_for(result, agent="claims-project"):
    found = [e for c, e in result["errors"].items() if c.rsplit("/", 1)[-1] == agent]
    # Errors about the API key are named after the key, not a chain.
    found = found or [e for c, e in result["errors"].items() if c.startswith("API key ")]
    (e,) = found
    return e
