'use strict';

(() => {
    const init = () => {
        const toggle = document.getElementById('require-school-id-2fa');
        const qrInput = document.getElementById('personal-id-qr-value');
        const qrControl = document.getElementById('personal-id-qr-control');
        const liveStatus = document.getElementById('personal-id-2fa-live-status');

        if (!toggle || !qrInput || !qrControl || !liveStatus) return;
        if (toggle.dataset.fortressUserManagementBound === '1') return;
        toggle.dataset.fortressUserManagementBound = '1';

        const editing = toggle.dataset.editing === '1';
        const hasQr = toggle.dataset.hasQr === '1';

        const sync2faForm = () => {
            const enabled = toggle.checked;
            const qrRequired = enabled && (!editing || !hasQr);

            qrInput.disabled = !enabled;
            qrInput.required = qrRequired;
            qrControl.style.opacity = enabled ? '1' : '.55';

            if (!enabled) {
                qrInput.value = '';
                qrInput.placeholder = '2FA disabled — no QR required';
                liveStatus.textContent = 'PASSWORD-ONLY LOGIN: this administrator will go directly to the dashboard after a valid password.';
            } else if (editing && hasQr) {
                qrInput.placeholder = 'Leave blank to keep the current QR';
                liveStatus.textContent = '2FA ENABLED: the existing QR stays registered unless you enter a replacement.';
            } else {
                qrInput.placeholder = 'Required: paste the Personal ID QR value';
                liveStatus.textContent = '2FA ENABLED: a Personal ID QR value is required before this account can be saved.';
            }
        };

        toggle.addEventListener('change', sync2faForm);
        sync2faForm();
    };

    window.FortressUserManagement = { init };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }
})();
