from directory import display_name, load_profile, manager_email, resolve_manager


def latest_login(profile):
    logins = profile.get("logins")
    if not logins:
        return None
    return logins[-1]


def login_summary(users, name):
    stamp = latest_login(load_profile(users, name))
    if stamp is None:
        return "never"
    return stamp.isoformat()


def escalation_chain(users, name, depth=2):
    chain = []
    current = name
    for _ in range(depth):
        manager = resolve_manager(users, current)
        if manager is None:
            break
        chain.append(manager["name"])
        current = manager["name"]
    return chain


def audit(users, names):
    rows = []
    for name in names:
        rows.append(
            (
                display_name(users, name),
                manager_email(users, name),
                login_summary(users, name),
                escalation_chain(users, name),
            )
        )
    return rows
