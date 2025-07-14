window.WalletApp = window.WalletApp || {};
WalletApp.Vault = WalletApp.Vault || {};

WalletApp.Vault.init = () => {
    if (!document.querySelector('.dashboard-container')) return;

    WalletApp.Vault.keyStorage = new WalletApp.Crypto.SecureKeyStorage();
    WalletApp.Vault.isFirstTimeVault = document.querySelectorAll("tbody tr").length === 0;
    WalletApp.Vault.currentEditId = null;
    WalletApp.Vault.currentEditServiceName = null;
    WalletApp.Vault.currentEditUsername = null;
    WalletApp.Vault.failedUnlockAttempts = 0;

    WalletApp.Vault.checkVaultStatus();
    WalletApp.Vault.initEventListeners();

    WalletApp.Vault.setupActivityTracking();
};

WalletApp.Vault.setupActivityTracking = () => {
    const activityEvents = ['click', 'keypress', 'scroll', 'mousemove', 'touchstart'];

    let lastActivity = Date.now();
    const throttleMs = 30000;

    const handleActivity = () => {
        const now = Date.now();
        if (now - lastActivity > throttleMs) {
            lastActivity = now;
            if (WalletApp.Vault.keyStorage) {
                WalletApp.Vault.keyStorage.extendTimeout();
            }
        }
    };

    activityEvents.forEach(event => {
        document.addEventListener(event, handleActivity, { passive: true });
    });
};

WalletApp.Vault.checkVaultStatus = () => {
    const rows = document.querySelectorAll("tbody tr");

    console.log('Vault status check:', {
        rowCount: rows.length,
        isFirstTimeVault: WalletApp.Vault.isFirstTimeVault
    });

    if (rows.length > 0) {
        const firstPasswordInput = rows[0].children[1].querySelector('input');

        if (firstPasswordInput.value && firstPasswordInput.value !== '••••••••••••') {
            WalletApp.Vault.keyStorage.vaultUnlocked = true;

            try {
                sessionStorage.setItem('vaultUnlocked', 'true');
                sessionStorage.setItem('vaultUnlockedTime', Date.now().toString());
            } catch (e) {
                console.warn('SessionStorage not available, using memory only');
            }
            console.log('Passwords already decrypted, vault is ready');
            return;
        }

        console.log('Existing passwords found but encrypted, prompting for master password unlock');
        WalletApp.Vault.showMasterPasswordModal();
        return;
    }

    const keyAvailable = WalletApp.Vault.keyStorage.isAvailable();
    console.log('No passwords found. Checking master password availability:', keyAvailable);

    if (keyAvailable) {
        console.log('Master password available but vault is empty - ready to save passwords');
        return;
    }

    console.log('No passwords and no master password - showing first-time setup modal');

    try {
        sessionStorage.removeItem('vaultUnlocked');
        sessionStorage.removeItem('vaultUnlockedTime');
        console.log('Cleared any stale session data');
    } catch (e) {
        console.warn('Could not clear session storage:', e);
    }

    WalletApp.Vault.keyStorage.clear();
    WalletApp.Vault.showMasterPasswordModal();
};

WalletApp.Vault.showMasterPasswordModal = () => {
    WalletApp.Vault.updateMasterPasswordModal(WalletApp.Vault.isFirstTimeVault && !WalletApp.Vault.keyStorage.vaultUnlocked);
    document.getElementById("masterPasswordModal").classList.remove('hidden');

    setTimeout(() => {
        const input = document.getElementById("masterPasswordInput");
        if (input) input.focus();
    }, 100);
};

WalletApp.Vault.hideMasterPasswordModal = () => {
    document.getElementById("masterPasswordModal").classList.add('hidden');
    document.getElementById("masterPasswordInput").value = '';
    document.getElementById("unlockError").classList.add('hidden');
};

WalletApp.Vault.updateMasterPasswordModal = (isFirstTime) => {
    const modalTitle = document.getElementById("modalTitle");
    const modalDisclaimer = document.querySelector(".modal-disclaimer");
    const unlockBtnText = document.getElementById("unlockBtnText");
    const masterPasswordInput = document.getElementById("masterPasswordInput");

    if (isFirstTime) {
        modalTitle.innerHTML = "🔐 Set Your Master Password";
        unlockBtnText.textContent = "🔒 Create Vault";
        masterPasswordInput.placeholder = "Create a strong master password";

        modalDisclaimer.innerHTML = `
            🔒 <strong>Important:</strong> Your master password is the key to your vault.
            It encrypts all your passwords and never leaves your browser.
            <strong>Choose a strong, memorable password - you cannot recover it if forgotten!</strong>
        `;
    } else {
        modalTitle.innerHTML = "🔑 Unlock Your Vault";
        unlockBtnText.textContent = "🔓 Unlock Vault";
        masterPasswordInput.placeholder = "Enter your master password";

        modalDisclaimer.innerHTML = `
            🔒 Your master password is never sent to our servers.
            All encryption happens locally in your browser.
        `;
    }
};

WalletApp.Vault.submitMasterPassword = async () => {
    const pw = document.getElementById("masterPasswordInput").value.trim();
    const errorElement = document.getElementById("unlockError");

    errorElement.classList.add('hidden');

    if (!pw) {
        const message = WalletApp.Vault.isFirstTimeVault && !WalletApp.Vault.keyStorage.vaultUnlocked ?
            'Please create your master password' :
            'Please enter your master password';
        WalletApp.showToast(message, 'error');
        return;
    }

    if (WalletApp.Vault.isFirstTimeVault && !WalletApp.Vault.keyStorage.vaultUnlocked) {
        const strengthCheck = WalletApp.Crypto.validatePasswordStrength(pw);
        if (!strengthCheck.isStrong) {
            WalletApp.showToast('Master password is too weak. Please choose a stronger password.', 'error');
            return;
        }
    }

    WalletApp.setButtonLoading('unlockBtn', true);

    try {
        if (WalletApp.Vault.isFirstTimeVault && !WalletApp.Vault.keyStorage.vaultUnlocked) {
            await WalletApp.Vault.keyStorage.set(pw);
            WalletApp.Vault.hideMasterPasswordModal();
            WalletApp.showToast('Welcome! Your secure vault has been created.');

            try {
                await fetch('/vault/unlock-success', { method: 'POST' });
            } catch (e) {
                console.warn('Could not notify server of successful unlock:', e);
            }
        } else {
            await WalletApp.Vault.unlockVault(pw);
        }

        if (window.pendingAction) {
            const action = window.pendingAction;
            window.pendingAction = null;
            setTimeout(action, 100);
        }
    } catch (error) {
        console.error('Master password submission failed:', error);

        WalletApp.Vault.failedUnlockAttempts++;

        try {
            await fetch('/vault/unlock-failed', { method: 'POST' });
        } catch (e) {
            console.warn('Could not notify server of failed unlock:', e);
        }

        const message = WalletApp.Vault.isFirstTimeVault && !WalletApp.Vault.keyStorage.vaultUnlocked ?
            'Failed to create vault. Please try again.' :
            'Incorrect master password. Please try again.';
        WalletApp.showToast(message, 'error');

        if (WalletApp.Vault.failedUnlockAttempts >= 3) {
            WalletApp.showToast('Multiple failed attempts detected. Please wait before trying again.', 'warning');
        }
    } finally {
        WalletApp.setButtonLoading('unlockBtn', false);
        document.getElementById("masterPasswordInput").value = '';
    }
};

WalletApp.Vault.unlockVault = async (password) => {
    const rows = document.querySelectorAll("tbody tr");
    let decryptionSuccessful = false;

    for (let row of rows) {
        const td = row.children[1];
        const encrypted = WalletApp.Crypto.base64ToArrayBuffer(td.getAttribute("data-encrypted"));
        const iv = WalletApp.Crypto.base64ToArrayBuffer(td.getAttribute("data-iv"));
        const salt = WalletApp.Crypto.base64ToArrayBuffer(td.getAttribute("data-salt"));

        try {
            td.querySelector("input").value = await WalletApp.Crypto.decryptPassword(encrypted, iv, salt, password);
            decryptionSuccessful = true;
        } catch (error) {
            console.error('Decryption failed for entry:', error);
            document.getElementById("unlockError").classList.remove('hidden');
            throw error; // Re-throw to trigger failed attempt tracking
        }
    }

    if (decryptionSuccessful || rows.length === 0) {
        await WalletApp.Vault.keyStorage.set(password);
        WalletApp.Vault.hideMasterPasswordModal();
        WalletApp.showToast(`Vault unlocked! Found ${rows.length} password${rows.length !== 1 ? 's' : ''}.`);

        WalletApp.Vault.failedUnlockAttempts = 0;

        try {
            await fetch('/vault/unlock-success', { method: 'POST' });
        } catch (e) {
            console.warn('Could not notify server of successful unlock:', e);
        }

        document.getElementById("unlockError").classList.add('hidden');
    }
};

WalletApp.Vault.requireMasterPassword = (callback) => {
    if (WalletApp.Vault.keyStorage.isAvailable()) {
        WalletApp.Vault.keyStorage.extendTimeout();
        return true;
    }

    if (WalletApp.Vault.keyStorage.shouldShowUnlockModal()) {
        console.log('Master password required for action');
        WalletApp.Vault.showMasterPasswordModal();
        window.pendingAction = callback;
        return false;
    }

    return true;
};

WalletApp.Vault.generatePassword = () => {
    try {
        const options = {
            length: Math.max(12, Math.min(128, parseInt(document.getElementById("passwordLength")?.value) || 16)),
            includeUpper: document.getElementById("includeUpper")?.checked ?? true,
            includeLower: document.getElementById("includeLower")?.checked ?? true,
            includeNumbers: document.getElementById("includeNumbers")?.checked ?? true,
            includeSymbols: document.getElementById("includeSymbols")?.checked ?? true
        };

        const password = WalletApp.Crypto.generatePassword(options);
        const input = document.getElementById("generatedPasswordInput");
        if (input) {
            input.value = password;
            WalletApp.showToast('Password generated successfully!');
        }
    } catch (error) {
        WalletApp.showToast(error.message, 'error');
    }
};

WalletApp.Vault.toggleVisibility = (id, toggleBtn) => {
    if (!WalletApp.Vault.requireMasterPassword(() => WalletApp.Vault.toggleVisibility(id, toggleBtn))) return;

    const input = document.getElementById(id);
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.innerHTML = isPassword ? "🙈 Hide" : "👁️ Show";
};

WalletApp.Vault.copyToClipboard = async (id) => {
    if (!WalletApp.Vault.requireMasterPassword(() => WalletApp.Vault.copyToClipboard(id))) return;

    const input = document.getElementById(id);
    const originalType = input.type;

    if (!input.value) {
        WalletApp.showToast('No password to copy', 'error');
        return;
    }

    try {
        await navigator.clipboard.writeText(input.value);
        WalletApp.showToast('Password copied to clipboard!');
    } catch (error) {
        if (originalType === 'password') input.type = 'text';
        input.select();
        input.setSelectionRange(0, input.value.length);

        try {
            document.execCommand('copy');
            WalletApp.showToast('Password copied to clipboard!');
        } catch (fallbackError) {
            WalletApp.showToast('Failed to copy password', 'error');
        }

        if (originalType === 'password') input.type = 'password';
    }
};

WalletApp.Vault.openEditModal = (id, inputId, serviceName, username) => {
    if (!WalletApp.Vault.requireMasterPassword(() => WalletApp.Vault.openEditModal(id, inputId, serviceName, username))) return;

    WalletApp.Vault.currentEditId = id;
    WalletApp.Vault.currentEditServiceName = serviceName;
    WalletApp.Vault.currentEditUsername = username;

    document.getElementById("editLabel").textContent = `Editing password for "${serviceName}"`;
    document.getElementById("editUsernameInput").value = username || "";
    document.getElementById("editPasswordInput").value = "";
    document.getElementById("editModal").classList.remove('hidden');

    setTimeout(() => {
        const usernameInput = document.getElementById("editUsernameInput");
        if (usernameInput) usernameInput.focus();
    }, 100);
};

WalletApp.Vault.closeEditModal = () => {
    document.getElementById("editModal").classList.add('hidden');
    WalletApp.Vault.currentEditId = null;
    WalletApp.Vault.currentEditServiceName = null;
    WalletApp.Vault.currentEditUsername = null;
};

WalletApp.Vault.handleEditSubmit = async () => {
    const newPassword = document.getElementById("editPasswordInput").value;
    const newUsername = document.getElementById("editUsernameInput").value.trim();

    if (!newPassword.trim()) {
        WalletApp.showToast('Password cannot be empty', 'error');
        return;
    }

    const strengthCheck = WalletApp.Crypto.validatePasswordStrength(newPassword);
    if (!strengthCheck.isStrong) {
        WalletApp.showToast('Password is too weak. Please choose a stronger password.', 'error');
        return;
    }

    if (!WalletApp.Vault.requireMasterPassword(() => WalletApp.Vault.handleEditSubmit())) return;

    WalletApp.setButtonLoading('editBtn', true);

    try {
        const { encrypted, iv, salt } = await WalletApp.Crypto.encryptPassword(newPassword, WalletApp.Vault.keyStorage);

        const payload = new URLSearchParams();
        payload.append("id", WalletApp.Vault.currentEditId);
        payload.append("username", newUsername || "");
        payload.append("encrypted", WalletApp.Crypto.arrayBufferToBase64(encrypted));
        payload.append("iv", WalletApp.Crypto.arrayBufferToBase64(iv));
        payload.append("salt", WalletApp.Crypto.arrayBufferToBase64(salt));

        const response = await fetch("/vault/edit", {
            method: "POST",
            body: payload
        });

        if (response.ok) {
            WalletApp.showToast(`Password for "${WalletApp.Vault.currentEditServiceName}" updated successfully!`);
            setTimeout(() => location.reload(), 1000);
        } else {
            throw new Error('Server error');
        }
    } catch (error) {
        console.error('Edit failed:', error);
        WalletApp.showToast('Failed to update password. Please try again.', 'error');
    } finally {
        WalletApp.setButtonLoading('editBtn', false);
    }
};

WalletApp.Vault.handleGenerateSubmit = async (e) => {
    e.preventDefault();

    const serviceName = document.getElementById("serviceNameInput").value.trim();
    const username = document.getElementById("usernameInput").value.trim();
    const plaintext = document.getElementById("generatedPasswordInput").value;

    if (!serviceName) {
        WalletApp.showToast('Please enter a service name', 'error');
        return;
    }

    if (!plaintext) {
        WalletApp.showToast('Please generate a password first', 'error');
        return;
    }

    const strengthCheck = WalletApp.Crypto.validatePasswordStrength(plaintext);
    if (!strengthCheck.isStrong) {
        WalletApp.showToast('Generated password is too weak. Please generate a stronger one.', 'error');
        return;
    }

    if (!WalletApp.Vault.requireMasterPassword(() => WalletApp.Vault.handleGenerateSubmit(e))) return;

    WalletApp.setButtonLoading('saveBtn', true);

    try {
        const { encrypted, iv, salt } = await WalletApp.Crypto.encryptPassword(plaintext, WalletApp.Vault.keyStorage);

        const payload = new URLSearchParams();
        payload.append("serviceName", serviceName);
        payload.append("username", username || "");
        payload.append("encrypted", WalletApp.Crypto.arrayBufferToBase64(encrypted));
        payload.append("iv", WalletApp.Crypto.arrayBufferToBase64(iv));
        payload.append("salt", WalletApp.Crypto.arrayBufferToBase64(salt));

        const response = await fetch("/vault/generate", {
            method: "POST",
            body: payload
        });

        if (response.ok) {
            const displayName = username ? `${serviceName} (${username})` : serviceName;
            WalletApp.showToast(`Password for "${displayName}" saved successfully!`);
            setTimeout(() => location.reload(), 1000);
        } else {
            throw new Error('Server error');
        }
    } catch (error) {
        console.error('Save failed:', error);
        WalletApp.showToast('Failed to save password. Please try again.', 'error');
    } finally {
        WalletApp.setButtonLoading('saveBtn', false);
    }
};

WalletApp.Vault.initEventListeners = () => {
    document.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = btn.getAttribute('data-id');
            const serviceName = btn.getAttribute('data-service-name');
            const username = btn.getAttribute('data-username');
            const inputId = btn.getAttribute('data-input-id');
            WalletApp.Vault.openEditModal(id, inputId, serviceName, username);
        });
    });

    document.getElementById("confirmEditBtn")?.addEventListener("click", WalletApp.Vault.handleEditSubmit);
    document.getElementById("generateForm")?.addEventListener("submit", WalletApp.Vault.handleGenerateSubmit);

    document.getElementById("masterPasswordInput")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            WalletApp.Vault.submitMasterPassword().catch(console.error);
        }
    });

    document.getElementById("editPasswordInput")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            WalletApp.Vault.handleEditSubmit().catch(console.error);
        }
    });

    document.getElementById("editUsernameInput")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            document.getElementById("editPasswordInput").focus();
        }
    });

    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-overlay')) {
            if (e.target.id === 'editModal') {
                WalletApp.Vault.closeEditModal();
            }
        }
    });
};

window.submitMasterPassword = () => WalletApp.Vault.submitMasterPassword();
window.generatePassword = () => WalletApp.Vault.generatePassword();
window.toggleVisibility = (id, btn) => WalletApp.Vault.toggleVisibility(id, btn);
window.copyToClipboard = (id) => WalletApp.Vault.copyToClipboard(id);
window.closeEditModal = () => WalletApp.Vault.closeEditModal();

document.addEventListener('DOMContentLoaded', () => {
    WalletApp.Vault.init();
});

console.log('WalletApp.Vault module loaded');