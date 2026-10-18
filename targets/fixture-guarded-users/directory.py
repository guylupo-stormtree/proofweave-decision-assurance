def find_user(users, name):
    for user in users:
        if user.get("name") == name:
            return user
    return None


def load_profile(users, name):
    user = find_user(users, name)
    if user is None:
        return {}
    return user.get("profile", {})


def display_name(users, name):
    user = find_user(users, name)
    return user["display"] if user is not None else "anonymous"


def resolve_manager(users, name):
    user = find_user(users, name)
    if not user:
        return None
    return find_user(users, user.get("manager", ""))


def manager_email(users, name):
    manager = resolve_manager(users, name)
    if manager is None:
        return "none"
    return manager["email"].lower()
