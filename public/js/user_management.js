'use strict';

(() => {
    const initFactorEditor = () => {
        const toggle = document.getElementById('require-school-id-2fa');
        const qrInput = document.getElementById('personal-id-qr-value');
        const qrControl = document.getElementById('personal-id-qr-control');
        const liveStatus = document.getElementById('personal-id-2fa-live-status');
        const methodControl = document.getElementById('second-factor-method-control');
        const generatedConfig = document.getElementById('generated-qr-config');
        const generatedCopy = document.getElementById('generated-qr-config-copy');
        const methodInputs = Array.from(document.querySelectorAll('input[name="second_factor_type"]'));
        const statusChip = document.getElementById('two-factor-status-chip');

        if (!toggle || !qrInput || !qrControl || !liveStatus || !methodControl) return;
        if (toggle.dataset.fortressUserManagementBound === '1') return;
        toggle.dataset.fortressUserManagementBound = '1';

        const editing = toggle.dataset.editing === '1';
        const hasQr = toggle.dataset.hasQr === '1';
        const currentFactor = toggle.dataset.currentFactor === 'generated_qr' ? 'generated_qr' : 'personal_id';
        const currentAccount = toggle.dataset.currentAccount === '1';

        const selectedFactor = () => {
            const checked = methodInputs.find((input) => input.checked && !input.disabled);
            return checked?.value === 'generated_qr' ? 'generated_qr' : 'personal_id';
        };

        const sync2faForm = () => {
            const enabled = toggle.checked;
            const factor = selectedFactor();
            const usingPersonalId = enabled && factor === 'personal_id';
            const usingGeneratedQr = enabled && factor === 'generated_qr';
            const needsPersonalIdValue = usingPersonalId && (!editing || !hasQr || currentFactor !== 'personal_id');

            methodControl.disabled = !enabled;
            methodControl.classList.toggle('is-disabled', !enabled);

            qrControl.hidden = !usingPersonalId;
            qrInput.disabled = !usingPersonalId;
            qrInput.required = needsPersonalIdValue;

            if (generatedConfig) generatedConfig.hidden = !usingGeneratedQr;

            if (statusChip) {
                statusChip.classList.remove('is-off', 'is-personal', 'is-generated');
                if (!enabled) {
                    statusChip.classList.add('is-off');
                    statusChip.textContent = 'PASSWORD ONLY';
                } else if (usingGeneratedQr) {
                    statusChip.classList.add('is-generated');
                    statusChip.textContent = 'ISSUED QR';
                } else {
                    statusChip.classList.add('is-personal');
                    statusChip.textContent = 'PERSONAL ID QR';
                }
            }

            if (!enabled) {
                qrInput.value = '';
                liveStatus.textContent = 'PASSWORD-ONLY LOGIN: this administrator will continue directly after a valid password.';
                return;
            }

            if (usingGeneratedQr) {
                qrInput.value = '';
                liveStatus.textContent = '';
                if (generatedCopy) {
                    if (!editing || currentFactor !== 'generated_qr' || !hasQr) {
                        generatedCopy.textContent = 'FortressAuth will issue a unique QR after this account is saved. The administrator must save or print it before leaving the one-time handoff screen.';
                    } else if (currentAccount) {
                        generatedCopy.textContent = 'This account already uses an issued QR. Another active administrator is required to regenerate the credential for the account currently signed in.';
                    } else {
                        generatedCopy.textContent = 'The existing issued QR remains valid unless “Issue a new QR on save” is selected.';
                    }
                }
                return;
            }

            if (editing && hasQr && currentFactor === 'personal_id') {
                qrInput.placeholder = 'Leave blank to keep the current QR';
                liveStatus.textContent = 'PERSONAL ID 2FA: the existing Personal ID stays registered unless you enter a replacement.';
            } else {
                qrInput.placeholder = 'Required: paste the Personal ID QR value';
                liveStatus.textContent = 'PERSONAL ID 2FA: paste the account owner’s Personal ID QR value before saving.';
            }
        };

        toggle.addEventListener('change', sync2faForm);
        methodInputs.forEach((input) => input.addEventListener('change', sync2faForm));
        sync2faForm();
    };

    const qrDataUrl = (container) => {
        const img = container.querySelector('img');
        if (img?.src?.startsWith('data:image/')) return img.src;
        const canvas = container.querySelector('canvas');
        if (canvas && typeof canvas.toDataURL === 'function') return canvas.toDataURL('image/png');
        return '';
    };

    const initGeneratedQrHandoff = () => {
        const handoff = document.getElementById('generated-qr-handoff');
        const target = document.getElementById('generated-qr-code');
        if (!handoff || !target || handoff.dataset.fortressQrBound === '1') return;
        handoff.dataset.fortressQrBound = '1';

        const credential = target.dataset.qrValue || '';
        if (!credential) return;

        if (typeof window.QRCode !== 'function') {
            target.innerHTML = '<div class="generated-qr-error">QR renderer unavailable. Reload this page before leaving it.</div>';
            return;
        }

        target.innerHTML = '';
        new window.QRCode(target, {
            text: credential,
            width: 260,
            height: 260,
            colorDark: '#0b0512',
            colorLight: '#ffffff',
            correctLevel: window.QRCode.CorrectLevel.H,
        });

        const download = document.getElementById('generated-qr-download');
        const print = document.getElementById('generated-qr-print');
        const dismiss = document.getElementById('generated-qr-dismiss');

        download?.addEventListener('click', () => {
            const url = qrDataUrl(target);
            if (!url) return;
            const username = (target.dataset.qrUsername || 'administrator').replace(/[^A-Za-z0-9_-]+/g, '_');
            const link = document.createElement('a');
            link.href = url;
            link.download = `FortressAuth-2FA-${username}.png`;
            document.body.appendChild(link);
            link.click();
            link.remove();
        });

        print?.addEventListener('click', () => {
            handoff.classList.add('print-qr-handoff');
            window.print();
            window.setTimeout(() => handoff.classList.remove('print-qr-handoff'), 300);
        });

        dismiss?.addEventListener('click', () => {
            handoff.classList.add('closing');
            window.setTimeout(() => handoff.remove(), 180);
        });
    };


    const initSuperAdminPasswordTools = () => {
        const field = document.getElementById('superadmin-reset-password');
        if (!field || field.dataset.fortressPasswordToolsBound === '1') return;
        field.dataset.fortressPasswordToolsBound = '1';

        const form = field.closest('form');
        const generate = form?.querySelector('[data-generate-password]');
        const toggle = form?.querySelector('[data-toggle-password]');

        const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-';
        const randomPassword = (length = 18) => {
            const bytes = new Uint32Array(length);
            window.crypto.getRandomValues(bytes);
            return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('');
        };

        generate?.addEventListener('click', () => {
            field.value = randomPassword();
            field.type = 'text';
            field.focus();
            field.select();
            if (toggle) toggle.innerHTML = '<i class="fa-solid fa-eye-slash"></i> Hide';
        });

        toggle?.addEventListener('click', () => {
            const revealing = field.type === 'password';
            field.type = revealing ? 'text' : 'password';
            toggle.innerHTML = revealing
                ? '<i class="fa-solid fa-eye-slash"></i> Hide'
                : '<i class="fa-solid fa-eye"></i> Show';
            field.focus();
        });
    };


    const initRolePicker = () => {
        const picker = document.querySelector('[data-role-picker]');
        if (!picker || picker.dataset.fortressRoleBound === '1') return;
        picker.dataset.fortressRoleBound = '1';

        const input = picker.querySelector('[data-role-input]');
        const trigger = picker.querySelector('[data-role-trigger]');
        const menu = picker.querySelector('[data-role-menu]');
        const title = picker.querySelector('[data-role-title]');
        const description = picker.querySelector('[data-role-description]');
        const badge = picker.querySelector('[data-role-badge]');
        const triggerIcon = picker.querySelector('.fortress-role-trigger-icon i');
        const options = Array.from(picker.querySelectorAll('[data-role-option]'));
        if (!input || !trigger || !menu || options.length === 0) return;

        const setOpen = (open) => {
            menu.hidden = !open;
            picker.classList.toggle('open', open);
            trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
        };

        const choose = (option, close = true) => {
            const value = option.dataset.roleOption === 'superadmin' ? 'superadmin' : 'admin';
            input.value = value;
            picker.dataset.roleValue = value;
            options.forEach((item) => {
                const selected = item === option;
                item.classList.toggle('selected', selected);
                item.setAttribute('aria-selected', selected ? 'true' : 'false');
            });
            if (title) title.textContent = option.dataset.roleTitleValue || (value === 'superadmin' ? 'Super Admin' : 'Admin');
            if (description) description.textContent = option.dataset.roleDescriptionValue || '';
            if (badge) badge.textContent = option.dataset.roleBadgeValue || '';
            if (triggerIcon) {
                triggerIcon.className = `fa-solid ${option.dataset.roleIcon || (value === 'superadmin' ? 'fa-crown' : 'fa-user-shield')}`;
            }
            picker.classList.toggle('is-superadmin', value === 'superadmin');
            if (close) setOpen(false);
        };

        trigger.addEventListener('click', () => {
            if (trigger.disabled) return;
            setOpen(menu.hidden);
        });

        options.forEach((option) => option.addEventListener('click', () => choose(option)));

        document.addEventListener('click', (event) => {
            if (!picker.contains(event.target)) setOpen(false);
        });

        picker.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                setOpen(false);
                trigger.focus();
                return;
            }
            if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && document.activeElement === trigger) {
                event.preventDefault();
                setOpen(true);
                const selectedIndex = Math.max(0, options.findIndex((item) => item.classList.contains('selected')));
                options[selectedIndex].focus();
            }
        });

        const initial = options.find((item) => item.dataset.roleOption === input.value) || options[0];
        choose(initial, false);
    };

    const initOperatorProfile = () => {
        const overlay = document.querySelector('[data-operator-profile]');
        if (!overlay || overlay.dataset.fortressProfileBound === '1') return;
        overlay.dataset.fortressProfileBound = '1';

        const closeHref = '/user_management.php#operator-directory';
        const closeProfile = () => {
            overlay.classList.add('closing');
            window.setTimeout(() => {
                window.location.href = closeHref;
            }, 150);
        };

        overlay.addEventListener('click', (event) => {
            if (event.target.classList.contains('operator-profile-backdrop')) {
                event.preventDefault();
                closeProfile();
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && document.body.contains(overlay)) {
                event.preventDefault();
                closeProfile();
            }
        });
    };

    const init = () => {
        initFactorEditor();
        initGeneratedQrHandoff();
        initSuperAdminPasswordTools();
        initRolePicker();
        initOperatorProfile();
    };

    window.FortressUserManagement = { init };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }
})();
