document.addEventListener('DOMContentLoaded', () => {

    const passwordToggleButton = document.getElementById('password-toggle');
    if (passwordToggleButton) {
        passwordToggleButton.addEventListener('click', togglePassword);
    }

    document.querySelectorAll('.password-input').forEach(input => {
        input.addEventListener('input', () => updateStrengthFeedback(input));
    });

    const generateBtn = document.getElementById('generate-password');
    if (generateBtn) {
        generateBtn.addEventListener('click', () => {
            const target = document.getElementById('new-password');
            if (target) {
                try {
                    target.value = generatePassword(12);
                    updateStrengthFeedback(target);
                } catch (error) {
                    // Fail closed: leave any existing input untouched.
                    const feedback = document.getElementById('strength-' + target.id);
                    if (feedback) {
                        feedback.textContent = 'Secure password generation is unavailable. Use a browser with Web Crypto support.';
                        feedback.style.color = 'red';
                    }
                }
            }
        });
    }

    setupUserSearch('add');
    setupUserSearch('update');
});

function togglePassword() {
    var passwordField = document.getElementById("password");
    var passwordToggle = document.getElementById("password-toggle");
    if (passwordField.type === "password") {
        passwordField.type = "text";
        passwordToggle.innerHTML = "Hide Password";
    } else {
        passwordField.type = "password";
        passwordToggle.innerHTML = "Show Password";
    }
}

// Rejection sampling avoids the bias of reducing every uint32 modulo bound.
function secureRandomInt(bound) {
    const range = 0x100000000;
    if (!Number.isSafeInteger(bound) || bound < 1 || bound > range) {
        throw new RangeError('Random bound must be an integer between 1 and 2^32.');
    }
    const cryptoProvider = globalThis.crypto;
    if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== 'function') {
        throw new Error('Secure password generation requires Web Crypto.');
    }
    const limit = range - (range % bound);
    const sample = new Uint32Array(1);
    do {
        cryptoProvider.getRandomValues(sample);
    } while (sample[0] >= limit);
    return sample[0] % bound;
}

function generatePassword(length = 12) {
    if (!Number.isSafeInteger(length)) {
        throw new TypeError('Password length must be an integer.');
    }
    // Match the server policy's minimum, not just the four categories below.
    length = Math.max(8, length);
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    // Keep this alphabet aligned with password_meets_requirements in functions.py.
    const specials = '!@#$%^&*(),.?":{}|<>';
    const categories = [upper, lower, digits, specials];
    const passwordChars = categories.map(alphabet => alphabet[secureRandomInt(alphabet.length)]);

    const all = categories.join('');
    for (let i = passwordChars.length; i < length; i++) {
        passwordChars.push(all[secureRandomInt(all.length)]);
    }

    // Fisher–Yates: each swap index is sampled uniformly, including i itself.
    for (let i = passwordChars.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
    }

    return passwordChars.join('');
}

function checkStrength(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(pw)) score++;
    if (score <= 1) return 'Weak';
    if (score === 2 || score === 3) return 'Moderate';
    return 'Strong';
}

function updateStrengthFeedback(input) {
    const feedback = document.getElementById('strength-' + input.id);
    if (!feedback) return;
    const result = checkStrength(input.value);
    let color = 'red';
    if (result === 'Moderate') color = 'orange';
    if (result === 'Strong') color = 'green';
    feedback.textContent = result;
    feedback.style.color = color;
}

// Export for Node.js testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { generatePassword, secureRandomInt };
}

function setupUserSearch(prefix) {
    const searchBtn = document.getElementById(`search-button-${prefix}`);
    const searchInput = document.getElementById(`search-user-${prefix}`);
    const resultDiv = document.getElementById(`search-result-${prefix}`);
    const list = document.getElementById(`share-list-${prefix}`);

    if (!searchBtn || !searchInput || !resultDiv || !list) return;

    searchBtn.addEventListener('click', () => {
        const username = searchInput.value.trim().toUpperCase();
        if (!username) return;
        fetch(`/search_user?username=${encodeURIComponent(username)}`)
            .then(resp => resp.json())
            .then(data => {
                if (data.found && /^[0-9a-f]{32}$/.test(data.auth_identity)) {
                    resultDiv.textContent = 'User found';
                    if (!list.querySelector(`li[data-id="${data.auth_identity}"]`)) {
                        const li = document.createElement('li');
                        li.dataset.id = data.auth_identity;
                        li.className = 'list-group-item d-flex justify-content-between align-items-center';
                        li.textContent = data.username;
                        const removeBtn = document.createElement('button');
                        removeBtn.type = 'button';
                        removeBtn.className = 'btn btn-sm btn-danger remove-user';
                        removeBtn.textContent = 'Remove';
                        removeBtn.addEventListener('click', () => li.remove());
                        const hidden = document.createElement('input');
                        hidden.type = 'hidden';
                        hidden.name = 'shared_users';
                        hidden.value = data.auth_identity;
                        li.appendChild(removeBtn);
                        li.appendChild(hidden);
                        list.appendChild(li);
                    }
                } else {
                    resultDiv.textContent = 'User not found';
                }
            });
    });

    list.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-user')) {
            e.target.closest('li').remove();
        }
    });
}
