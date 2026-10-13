"""Technical bounds for account mutations; never normalize password contents."""
from passlib.utils import MAX_PASSWORD_SIZE

USERNAME_LIMIT = 255  # User.username is String(255), measured after uppercasing.


def account_fields(form, *, allow_empty_password=False):
    """Return normalized username, unchanged password, or a safe form error.

    Scrypt's Passlib adapter validates Unicode character count before UTF-8
    encoding. Do not substitute a byte limit that rejects supported passwords.
    Encoding is still checked explicitly so malformed Unicode cannot reach hashing.
    """
    for name in ('username', 'password'):
        if len(form.getlist(name)) != 1:
            return None, None, 'Provide one username and one password field.'
    username, password = form['username'], form['password']
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, 'Username and password must be text.'
    username = username.upper()
    if not username.strip() or len(username) > USERNAME_LIMIT:
        return None, None, 'Username must contain 1 to 255 characters after capitalization.'
    if len(password) > MAX_PASSWORD_SIZE:
        return None, None, f'Password must not exceed {MAX_PASSWORD_SIZE} characters.'
    try:
        username.encode('utf-8')
        password.encode('utf-8')
    except UnicodeEncodeError:
        return None, None, 'Username and password must contain valid Unicode text.'
    if not password and not allow_empty_password:
        return None, None, 'Password is required.'
    return username, password, None
