window.WalletApp = window.WalletApp || {};
WalletApp.Crypto = WalletApp.Crypto || {};

const MIN_PASSWORD_LENGTH = 12;

WalletApp.Crypto.validatePasswordStrength = (password) => {
    const checks = {
        length: password.length >= MIN_PASSWORD_LENGTH,
        hasUpper: /[A-Z]/.test(password),
        hasLower: /[a-z]/.test(password),
        hasNumbers: /\d/.test(password),
        hasSpecial: /[!@#$%^&*(),.?":{}|<>_+=\-\[\]\\;'\/~`]/.test(password),
        noCommonPatterns: !/^(password|123456|qwerty|admin|letmein)/i.test(password)
    };

    const strength = Object.values(checks).filter(Boolean).length;
    const isStrong = strength >= 5 && checks.length && checks.hasUpper && checks.hasLower;

    return {
        isStrong,
        strength,
        checks,
        score: Math.min(100, (strength / 6) * 100)
    };
};

WalletApp.Crypto.base64ToArrayBuffer = (base64) => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
};

WalletApp.Crypto.arrayBufferToBase64 = (buffer) => {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};

WalletApp.Crypto.deriveKey = async (password, salt, keyMaterial = null) => {
    try {
        let km = keyMaterial;

        if (!km) {
            km = await crypto.subtle.importKey(
                "raw",
                new TextEncoder().encode(password),
                { name: "PBKDF2" },
                false,
                ["deriveKey"]
            );
        }

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            km,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        console.error('Key derivation failed:', error);
        throw new Error('Failed to derive encryption key');
    }
};

WalletApp.Crypto.SecureKeyStorage = class {
    constructor() {
        this.derivedKey = null;
        this.keyTimeout = null;
        this.vaultUnlocked = false;
        this.KEY_TIMEOUT_MINUTES = 15;
        this.lastActivityTime = Date.now();
    }

    async set(password) {
        try {
            this.derivedKey = null;

            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                new TextEncoder().encode(password),
                { name: "PBKDF2" },
                false,
                ["deriveKey"]
            );

            this.derivedKey = { keyMaterial, password: password };
            this.vaultUnlocked = true;
            this.lastActivityTime = Date.now();

            try {
                sessionStorage.setItem('vaultUnlocked', 'true');
                sessionStorage.setItem('vaultUnlockedTime', this.lastActivityTime.toString());
            } catch (e) {
                console.warn('SessionStorage not available, using memory only');
            }

            this.resetTimeout();
            return true;
        } catch (error) {
            console.error('Failed to store key securely:', error);
            return false;
        }
    }

    clear() {
        if (this.derivedKey && this.derivedKey.password) {
            const randomStr = crypto.getRandomValues(new Uint8Array(this.derivedKey.password.length));
            this.derivedKey.password = String.fromCharCode(...randomStr);
        }

        this.derivedKey = null;
        this.vaultUnlocked = false;
        this.lastActivityTime = 0;

        try {
            sessionStorage.removeItem('vaultUnlocked');
            sessionStorage.removeItem('vaultUnlockedTime');
        } catch (e) {
            // Ignore if sessionStorage not available
        }

        clearTimeout(this.keyTimeout);
        this.keyTimeout = null;
    }

    isAvailable() {
        if (this.derivedKey !== null && this.vaultUnlocked) {
            return true;
        }

        try {
            const wasUnlocked = sessionStorage.getItem('vaultUnlocked');
            const unlockedTime = parseInt(sessionStorage.getItem('vaultUnlockedTime') || '0');
            const now = Date.now();
            const timeElapsed = now - unlockedTime;
            const maxAge = this.KEY_TIMEOUT_MINUTES * 60 * 1000;

            if (wasUnlocked === 'true' && timeElapsed < maxAge) {
                this.vaultUnlocked = true;
                this.lastActivityTime = now;
                return true;
            }
        } catch (e) {
            // SessionStorage not available, fall back to memory only
        }

        return false;
    }

    resetTimeout() {
        clearTimeout(this.keyTimeout);
        this.lastActivityTime = Date.now();

        try {
            sessionStorage.setItem('vaultUnlockedTime', this.lastActivityTime.toString());
        } catch (e) {
            // Ignore if sessionStorage not available
        }

        this.keyTimeout = setTimeout(() => {
            console.log('Master password session expired after', this.KEY_TIMEOUT_MINUTES, 'minutes of inactivity');
            this.clear();
            if (typeof WalletApp !== 'undefined' && WalletApp.showToast) {
                WalletApp.showToast('Session expired due to inactivity. Please enter your master password again.', 'warning');
            }

            if (window.location.pathname.startsWith('/vault/') &&
                typeof WalletApp !== 'undefined' &&
                WalletApp.Vault &&
                WalletApp.Vault.showMasterPasswordModal) {
                WalletApp.Vault.showMasterPasswordModal();
            }
        }, this.KEY_TIMEOUT_MINUTES * 60 * 1000);
    }

    extendTimeout() {
        if (this.isAvailable()) {
            this.resetTimeout();
        }
    }

    getKeyMaterial() {
        return this.derivedKey ? this.derivedKey.keyMaterial : null;
    }

    getPassword() {
        return this.derivedKey ? this.derivedKey.password : null;
    }

    shouldShowUnlockModal() {
        return !this.isAvailable();
    }
};

WalletApp.Crypto.encryptPassword = async (plainTextPassword, keyStorage) => {
    try {
        if (!keyStorage.isAvailable()) {
            throw new Error('Master password required');
        }

        keyStorage.extendTimeout();

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const password = keyStorage.getPassword();
        const key = await WalletApp.Crypto.deriveKey(password, salt);

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            new TextEncoder().encode(plainTextPassword)
        );

        return { encrypted, iv, salt };
    } catch (error) {
        console.error('Encryption failed:', error);
        throw new Error('Failed to encrypt password');
    }
};

WalletApp.Crypto.decryptPassword = async (encryptedData, iv, salt, password) => {
    try {
        const key = await WalletApp.Crypto.deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            encryptedData
        );
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Failed to decrypt password');
    }
};

WalletApp.Crypto.generatePassword = (options = {}) => {
    const defaults = {
        length: 16,
        includeUpper: true,
        includeLower: true,
        includeNumbers: true,
        includeSymbols: true
    };

    const config = { ...defaults, ...options };

    const charsetMap = {
        includeUpper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        includeLower: "abcdefghijklmnopqrstuvwxyz",
        includeNumbers: "0123456789",
        includeSymbols: "!@#$%^&*()_+-=[]{}|;:,.<>?"
    };

    let charset = "";
    for (let key in charsetMap) {
        if (config[key]) {
            charset += charsetMap[key];
        }
    }

    if (!charset) {
        throw new Error('Please select at least one character type');
    }

    const length = Math.max(MIN_PASSWORD_LENGTH, Math.min(128, config.length));
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    return Array.from(array, x => charset[x % charset.length]).join('');
};

console.log('WalletApp.Crypto module loaded');