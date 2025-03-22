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