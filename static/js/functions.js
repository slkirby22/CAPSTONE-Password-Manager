document.addEventListener('DOMContentLoaded', () => {

    const togglePasswordButtons = document.querySelectorAll('[id^="toggle-password-"]');

    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', () => {
            const passwordId = button.id.replace('toggle-password-', '');
            togglePasswordList(passwordId);
        });
    });

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
                target.value = generatePassword(12);
                updateStrengthFeedback(target);
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

function togglePasswordList(passwordid) {
    var passwordField = document.getElementById("password" + passwordid);
    var passwordToggle = document.getElementById("toggle-password-" + passwordid);
    if (passwordField.type === "password") {
        passwordField.type = "text";
        passwordToggle.innerHTML = "Hide Password";
    } else {
        passwordField.type = "password";
        passwordToggle.innerHTML = "Show Password";
    }
}

function generatePassword(length) {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const specials = '!@#$%^&*()_+~`|}{[]:;?><,./-=';

    if (length < 4) {
        length = 4; // minimum to include one of each category
    }

    const passwordChars = [];
    passwordChars.push(upper.charAt(Math.floor(Math.random() * upper.length)));
    passwordChars.push(lower.charAt(Math.floor(Math.random() * lower.length)));
    passwordChars.push(digits.charAt(Math.floor(Math.random() * digits.length)));
    passwordChars.push(specials.charAt(Math.floor(Math.random() * specials.length)));

    const all = upper + lower + digits + specials;
    for (let i = passwordChars.length; i < length; i++) {
        passwordChars.push(all.charAt(Math.floor(Math.random() * all.length)));
    }

    // Shuffle to ensure random order
    for (let i = passwordChars.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
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
    module.exports = { generatePassword };
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
                if (data.found) {
                    resultDiv.textContent = 'User found';
                    if (!list.querySelector(`li[data-id="${data.id}"]`)) {
                        const li = document.createElement('li');
                        li.dataset.id = data.id;
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
                        hidden.value = data.id;
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
