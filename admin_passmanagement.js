document.addEventListener("DOMContentLoaded", function() {
    // Modal elements
    const resetPasswordModal = document.getElementById("resetPasswordModal");
    const changePasswordModal = document.getElementById("changePasswordModal");
    const closeButtons = document.querySelectorAll(".close");
    
    // Form elements
    const resetPasswordForm = document.getElementById("resetPasswordForm");
    const changePasswordForm = document.getElementById("changePasswordForm");
    const cancelResetBtn = document.getElementById("cancelResetBtn");
    const cancelChangeBtn = document.getElementById("cancelChangeBtn");
    
    // Password field elements
    const passwordFields = document.querySelectorAll(".password-field input");
    const togglePasswordButtons = document.querySelectorAll(".toggle-password");
    
    // Search functionality for users table
    const userSearch = document.getElementById("userSearch");
    const userRows = document.querySelectorAll(".users-table tbody tr");
    
    // Initialize password strength meters
    initPasswordStrengthMeters();
    
    // Event listeners for reset password buttons
    document.querySelectorAll(".reset-btn").forEach(button => {
        button.addEventListener("click", function() {
            const userID = this.getAttribute("data-id");
            const email = this.getAttribute("data-email");
            const requestID = this.getAttribute("data-request");
            
            document.getElementById("resetUserID").value = userID;
            document.getElementById("resetEmail").value = email;
            document.getElementById("requestID").value = requestID;
            
            resetPasswordModal.style.display = "block";
        });
    });
    
    // Event listeners for change password buttons
    document.querySelectorAll(".change-pwd-btn").forEach(button => {
        button.addEventListener("click", function() {
            const userID = this.getAttribute("data-id");
            const email = this.getAttribute("data-email");
            
            document.getElementById("changeUserID").value = userID;
            document.getElementById("changeEmail").value = email;
            
            changePasswordModal.style.display = "block";
        });
    });
    
    // Close modals when clicking the X button
    closeButtons.forEach(button => {
        button.addEventListener("click", function() {
            resetPasswordModal.style.display = "none";
            changePasswordModal.style.display = "none";
            
            // Reset forms
            resetPasswordForm.reset();
            changePasswordForm.reset();
            resetPasswordStrengthMeters();
        });
    });
    
    // Close modals when clicking outside the modal content
    window.addEventListener("click", function(event) {
        if (event.target === resetPasswordModal) {
            resetPasswordModal.style.display = "none";
            resetPasswordForm.reset();
            resetPasswordStrengthMeters();
        }
        if (event.target === changePasswordModal) {
            changePasswordModal.style.display = "none";
            changePasswordForm.reset();
            resetPasswordStrengthMeters();
        }
    });
    
    // Cancel buttons for modals
    cancelResetBtn.addEventListener("click", function() {
        resetPasswordModal.style.display = "none";
        resetPasswordForm.reset();
        resetPasswordStrengthMeters();
    });
    
    cancelChangeBtn.addEventListener("click", function() {
        changePasswordModal.style.display = "none";
        changePasswordForm.reset();
        resetPasswordStrengthMeters();
    });
    
    // Toggle password visibility
    togglePasswordButtons.forEach(button => {
        button.addEventListener("click", function() {
            const passwordField = this.previousElementSibling;
            
            if (passwordField.type === "password") {
                passwordField.type = "text";
                this.classList.remove("fa-eye");
                this.classList.add("fa-eye-slash");
            } else {
                passwordField.type = "password";
                this.classList.remove("fa-eye-slash");
                this.classList.add("fa-eye");
            }
        });
    });
    
    // User search functionality
    userSearch.addEventListener("keyup", function() {
        const searchTerm = this.value.toLowerCase();
        
        userRows.forEach(row => {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    });
    
    // Reset Password Form Submission
    resetPasswordForm.addEventListener("submit", function(e) {
        e.preventDefault();
        
        // Validate passwords match
        const newPassword = document.getElementById("newPassword").value;
        const confirmPassword = document.getElementById("confirmPassword").value;
        
        if (newPassword !== confirmPassword) {
            showToast("Passwords do not match", "error");
            return;
        }
        
        // Prepare form data
        const formData = new FormData(this);
        
        // Send reset password request
        fetch("admin_resetpassword.php", {
            method: "POST",
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast(data.message, "success");
                resetPasswordModal.style.display = "none";
                resetPasswordForm.reset();
                
                // Refresh the page after short delay to show updated status
                setTimeout(() => {
                    location.reload();
                }, 2000);
            } else {
                showToast(data.message, "error");
            }
        })
        .catch(error => {
            console.error("Error:", error);
            showToast("An error occurred. Please try again.", "error");
        });
    });
    
    // Change Password Form Submission
    changePasswordForm.addEventListener("submit", function(e) {
        e.preventDefault();
        
        // Validate passwords match
        const newPassword = document.getElementById("userNewPassword").value;
        const confirmPassword = document.getElementById("userConfirmPassword").value;
        
        if (newPassword !== confirmPassword) {
            showToast("Passwords do not match", "error");
            return;
        }
        
        // Prepare form data
        const formData = new FormData(this);
        
        // Send change password request
        fetch("admin_changepassword.php", {
            method: "POST",
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast(data.message, "success");
                changePasswordModal.style.display = "none";
                changePasswordForm.reset();
            } else {
                showToast(data.message, "error");
            }
        })
        .catch(error => {
            console.error("Error:", error);
            showToast("An error occurred. Please try again.", "error");
        });
    });
    
    // Password strength meter initialization
    function initPasswordStrengthMeters() {
        const passwordInputs = [
            document.getElementById("newPassword"),
            document.getElementById("userNewPassword")
        ];
        
        const confirmInputs = [
            {
                input: document.getElementById("confirmPassword"),
                original: document.getElementById("newPassword"),
                matchDiv: document.getElementById("confirmPassword").parentElement.nextElementSibling
            },
            {
                input: document.getElementById("userConfirmPassword"),
                original: document.getElementById("userNewPassword"),
                matchDiv: document.getElementById("userConfirmPassword").parentElement.nextElementSibling
            }
        ];
        
        // Add password strength checking
        passwordInputs.forEach(input => {
            if (!input) return;
            
            const strengthMeter = input.parentElement.nextElementSibling.querySelector(".strength-meter");
            const strengthText = input.parentElement.nextElementSibling.querySelector(".strength-text span");
            
            input.addEventListener("input", function() {
                const strength = checkPasswordStrength(this.value);
                updatePasswordStrengthUI(strength, strengthMeter, strengthText);
            });
        });
        
        // Add password match checking
        confirmInputs.forEach(item => {
            if (!item.input || !item.original || !item.matchDiv) return;
            
            item.input.addEventListener("input", function() {
                checkPasswordsMatch(item.original.value, this.value, item.matchDiv);
            });
            
            item.original.addEventListener("input", function() {
                if (item.input.value) {
                    checkPasswordsMatch(this.value, item.input.value, item.matchDiv);
                }
            });
        });
    }
    
    // Check password strength
    function checkPasswordStrength(password) {
        if (!password) return { score: 0, text: "Weak" };
        
        let score = 0;
        
        // Length check
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        
        // Complexity checks
        if (/[A-Z]/.test(password)) score += 1;  // Uppercase
        if (/[a-z]/.test(password)) score += 1;  // Lowercase
        if (/[0-9]/.test(password)) score += 1;  // Numbers
        if (/[^A-Za-z0-9]/.test(password)) score += 1;  // Special characters
        
        // Determine strength level
        let strength = { score: 0, text: "Weak" };
        
        if (score <= 2) {
            strength = { score: 1, text: "Weak" };
        } else if (score <= 4) {
            strength = { score: 2, text: "Medium" };
        } else if (score <= 6) {
            strength = { score: 3, text: "Strong" };
        } else {
            strength = { score: 4, text: "Very Strong" };
        }
        
        return strength;
    }
    
    // Update password strength UI
    function updatePasswordStrengthUI(strength, meter, text) {
        // Remove all classes
        meter.classList.remove("weak", "medium", "strong", "very-strong");
        
        // Add appropriate class based on strength
        if (strength.score === 1) {
            meter.classList.add("weak");
            text.textContent = "Weak";
            text.style.color = "#f44336"; // Red
        } else if (strength.score === 2) {
            meter.classList.add("medium");
            text.textContent = "Medium";
            text.style.color = "#ff9800"; // Orange
        } else if (strength.score === 3) {
            meter.classList.add("strong");
            text.textContent = "Strong";
            text.style.color = "#2196F3"; // Blue
        } else if (strength.score === 4) {
            meter.classList.add("very-strong");
            text.textContent = "Very Strong";
            text.style.color = "#4CAF50"; // Green
        } else {
            text.textContent = "Weak";
            text.style.color = "#f44336"; // Red
        }
    }
    
    // Check if passwords match
    function checkPasswordsMatch(password1, password2, matchDiv) {
        if (!password1 || !password2) {
            matchDiv.textContent = "";
            return;
        }
        
        if (password1 === password2) {
            matchDiv.textContent = "Passwords match ✓";
            matchDiv.style.color = "#4CAF50"; // Green
        } else {
            matchDiv.textContent = "Passwords do not match ✗";
            matchDiv.style.color = "#f44336"; // Red
        }
    }
    
    // Reset password strength meters
    function resetPasswordStrengthMeters() {
        const strengthMeters = document.querySelectorAll(".strength-meter");
        const strengthTexts = document.querySelectorAll(".strength-text span");
        const matchDivs = document.querySelectorAll(".password-match");
        
        strengthMeters.forEach(meter => {
            meter.classList.remove("weak", "medium", "strong", "very-strong");
        });
        
        strengthTexts.forEach(text => {
            text.textContent = "Weak";
            text.style.color = "#f44336"; // Red
        });
        
        matchDivs.forEach(div => {
            div.textContent = "";
        });
    }
    
    // Show toast notification
    function showToast(message, type) {
        // Remove existing toast if any
        const existingToast = document.querySelector(".toast");
        if (existingToast) {
            existingToast.remove();
        }
        
        // Create new toast
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>${message}`;
        
        // Add to body
        document.body.appendChild(toast);
        
        // Show toast
        setTimeout(() => {
            toast.classList.add("show");
        }, 10);
        
        // Hide toast after 3 seconds
        setTimeout(() => {
            toast.classList.remove("show");
            setTimeout(() => {
                toast.remove();
            }, 300);
        }, 3000);
    }
});