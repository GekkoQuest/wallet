window.WalletApp = window.WalletApp || {};

WalletApp.showToast = (message, type = 'success') => {
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
};

WalletApp.setButtonLoading = (buttonId, isLoading) => {
    const textElement = document.getElementById(`${buttonId}Text`);
    const loaderElement = document.getElementById(`${buttonId}Loader`);

    if (!textElement || !loaderElement) return;

    const button = textElement.closest('button');

    if (isLoading) {
        textElement.classList.add('hidden');
        loaderElement.classList.remove('hidden');
        button.disabled = true;
    } else {
        textElement.classList.remove('hidden');
        loaderElement.classList.add('hidden');
        button.disabled = false;
    }
};

WalletApp.isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

WalletApp.isValidVerificationCode = (code) => {
    return code && /^\d{6}$/.test(code.trim());
};

WalletApp.showError = (message, containerId = null) => {
    let errorDiv = document.querySelector('.error-message');

    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-message mt-20';

        const targetElement = containerId ?
            document.getElementById(containerId) :
            document.querySelector('form');

        if (targetElement) {
            targetElement.after(errorDiv);
        }
    }

    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
};

WalletApp.clearError = () => {
    const errorDiv = document.querySelector('.error-message');
    if (errorDiv) {
        errorDiv.classList.add('hidden');
    }
};

WalletApp.showSuccess = (message) => {
    let successDiv = document.querySelector('.success-message');

    if (!successDiv) {
        successDiv = document.createElement('div');
        successDiv.className = 'generated-password-display mt-20';
        const form = document.querySelector('form');
        if (form) {
            form.after(successDiv);
        }
    }

    successDiv.textContent = message;
    successDiv.classList.remove('hidden');

    setTimeout(() => {
        successDiv.classList.add('hidden');
    }, 3000);
};

WalletApp.focusFirstInput = () => {
    const firstInput = document.querySelector('input[type="email"], input[type="text"], input[type="password"]');
    if (firstInput) {
        firstInput.focus();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    if (!document.querySelector('style[data-wallet-loading]')) {
        const style = document.createElement('style');
        style.setAttribute('data-wallet-loading', 'true');
        style.textContent = `
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
    }
});