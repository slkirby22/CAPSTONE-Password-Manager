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