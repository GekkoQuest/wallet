window.WalletApp = window.WalletApp || {};
WalletApp.Auth = WalletApp.Auth || {};

WalletApp.Auth.initLogin = () => {
    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');

    if (!form || !emailInput) return;

    emailInput.focus();

    form.addEventListener('submit', (e) => {
        const email = emailInput.value.trim();

        if (!email) {
            e.preventDefault();
            WalletApp.showError('Please enter your email address');
            return;
        }

        if (!WalletApp.isValidEmail(email)) {
            e.preventDefault();
            WalletApp.showError('Please enter a valid email address');
            return;
        }

        WalletApp.setButtonLoading('loginBtn', true);
    });

    emailInput.addEventListener('input', () => {
        WalletApp.clearError();
    });
};

WalletApp.Auth.initVerify = () => {
    const form = document.getElementById('verifyForm');
    const codeInput = document.getElementById('code');

    if (!form || !codeInput) return;

    codeInput.focus();

    codeInput.addEventListener('input', (e) => {
        let value = e.target.value.replace(/\D/g, '');

        if (value.length > 6) {
            value = value.slice(0, 6);
        }

        e.target.value = value;
        WalletApp.clearError();
    });

    codeInput.addEventListener('keypress', (e) => {
        if (!/\d/.test(e.key) && !['Backspace', 'Delete', 'Tab', 'Enter'].includes(e.key)) {
            e.preventDefault();
        }
    });

    form.addEventListener('submit', (e) => {
        const code = codeInput.value.trim();

        if (!code) {
            e.preventDefault();
            WalletApp.showError('Please enter the verification code');
            return;
        }

        if (!WalletApp.isValidVerificationCode(code)) {
            e.preventDefault();
            WalletApp.showError('Please enter the complete 6-digit code');
            return;
        }

        WalletApp.setButtonLoading('verifyBtn', true);
    });

    WalletApp.Auth.initResendCooldown();
};

WalletApp.Auth.initResendCooldown = () => {
    let resendCooldown = 0;
    let countdownInterval = null;

    const startCooldown = () => {
        resendCooldown = 60;
        const resendBtn = document.getElementById('resendBtn');
        const timerDiv = document.getElementById('resendTimer');
        const countdown = document.getElementById('countdown');

        if (!resendBtn || !timerDiv || !countdown) return;

        resendBtn.disabled = true;
        resendBtn.style.opacity = '0.5';
        timerDiv.classList.remove('hidden');

        countdownInterval = setInterval(() => {
            resendCooldown--;
            countdown.textContent = resendCooldown;

            if (resendCooldown <= 0) {
                clearInterval(countdownInterval);
                resendBtn.disabled = false;
                resendBtn.style.opacity = '1';
                timerDiv.classList.add('hidden');
            }
        }, 1000);
    };

    if (window.location.search.includes('resent=true')) {
        startCooldown();
    }

    const resendForm = document.querySelector('form[action="/send-code"]');
    if (resendForm) {
        resendForm.addEventListener('submit', () => {
            WalletApp.setButtonLoading('resendBtn', true);
        });
    }
};

document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('loginForm')) {
        WalletApp.Auth.initLogin();
    }

    if (document.getElementById('verifyForm')) {
        WalletApp.Auth.initVerify();
    }
});

console.log('WalletApp.Auth module loaded');