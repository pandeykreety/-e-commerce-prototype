// SECURE FRONTEND LOGIC & DOM MANIPULATION

// This script provides immediate, suitable feedback to the user on 
// security interactions (like password strength) directly in the browser.
// enforcement occurs solely on the backend to prevent request tampering.

document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    const pwStrengthContainer = document.getElementById('pw-container');

    if (passwordInput && pwStrengthContainer) {
        passwordInput.addEventListener('input', (e) => {
            const val = e.target.value;
            let checksPassed = 0;

            const hasLength = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasNum = /[0-9]/.test(val);
            const hasSpecial = /[\W_]/.test(val);

            if (hasLength) checksPassed++;
            if (hasUpper) checksPassed++;
            if (hasLower) checksPassed++;
            if (hasNum) checksPassed++;
            if (hasSpecial) checksPassed++;

            pwStrengthContainer.className = 'pw-strength-container'; // reset

            // Update UI checklist
            const updateReq = (id, condition) => {
                const el = document.getElementById(id);
                if (el) {
                    const icon = el.querySelector('.req-icon');
                    if (condition) {
                        el.style.color = 'var(--success)';
                        if (icon) icon.textContent = '✓';
                    } else {
                        el.style.color = 'var(--text-muted)';
                        if (icon) icon.textContent = '○';
                    }
                }
            }

            updateReq('req-length', hasLength);
            updateReq('req-upper', hasUpper);
            updateReq('req-lower', hasLower);
            updateReq('req-num', hasNum);
            updateReq('req-special', hasSpecial);

            const pwText = document.getElementById('pw-text');
            if (val.length === 0) {
                if (pwText) {
                    pwText.textContent = 'Strength: None';
                    pwText.style.color = 'var(--text-muted)';
                }
            } else if (checksPassed < 3) {
                pwStrengthContainer.classList.add('strength-weak');
                if (pwText) {
                    pwText.textContent = 'Strength: Weak (Insecure)';
                    pwText.style.color = 'var(--danger)';
                }
            } else if (checksPassed < 5) {
                pwStrengthContainer.classList.add('strength-medium');
                if (pwText) {
                    pwText.textContent = 'Strength: Medium (Acceptable)';
                    pwText.style.color = 'var(--warning)';
                }
            } else {
                pwStrengthContainer.classList.add('strength-strong');
                if (pwText) {
                    pwText.textContent = 'Strength: Strong (Secure)';
                    pwText.style.color = 'var(--accent)';
                }
            }
        });
    }

    // Password Visibility Toggle
    const togglePassword = document.getElementById('togglePassword');
    const password = document.getElementById('password');

    if (togglePassword && password) {
        togglePassword.addEventListener('click', function () {
            // toggle the type attribute
            const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
            password.setAttribute('type', type);

            // toggle the eye slash icon
            this.innerHTML = type === 'password'
                ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>'
                : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
        });
    }


    // CAPTCHA Reload Integration
    // Uses asynchronous fetch to obtain a new challenge without 
    // reloading the DOM, preventing form data loss during registration.

    const reloadCaptchaBtn = document.getElementById('reload_captcha');
    const captchaImg = document.getElementById('captcha_img');

    if (reloadCaptchaBtn && captchaImg) {
        reloadCaptchaBtn.addEventListener('click', async () => {
            try {
                // Add spinning animation to button 
                const svg = reloadCaptchaBtn.querySelector('svg');
                if (svg) svg.style.transform = 'rotate(180deg)';
                if (svg) svg.style.transition = 'transform 0.3s ease';

                const response = await fetch('/api/captcha');
                if (response.ok) {
                    const data = await response.json();
                    if (data.captcha_img) {
                        captchaImg.src = 'data:image/png;base64,' + data.captcha_img;
                    }
                }
                setTimeout(() => {
                    if (svg) svg.style.transform = 'rotate(0deg)';
                }, 300);
            } catch (error) {
                console.error('Error reloading CAPTCHA:', error);
            }
        });
    }
});
