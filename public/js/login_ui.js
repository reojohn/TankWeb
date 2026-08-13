document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('.auth-form');
    const password = document.getElementById('password');
    const toggle = document.getElementById('password-toggle');
    const submit = form ? form.querySelector('.primary-action[type="submit"]') : null;
    const fields = document.querySelectorAll('.input-shell input');
    const shell = document.querySelector('.auth-shell');
    const stageTitle = document.getElementById('login-stage-title');
    const stageMessage = document.getElementById('login-stage-message');
    const stageProgress = document.getElementById('login-stage-progress-bar');
    const scanPercent = document.getElementById('login-scan-percent');
    const stageSteps = Array.from(document.querySelectorAll('[data-login-step]'));
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    fields.forEach((input) => {
        const inputShell = input.closest('.input-shell');

        const syncValueState = () => {
            if (!inputShell) return;
            inputShell.classList.toggle('has-value', input.value.trim().length > 0);
        };

        syncValueState();
        input.addEventListener('input', syncValueState);
        input.addEventListener('focus', () => inputShell && inputShell.classList.add('is-focused'));
        input.addEventListener('blur', () => inputShell && inputShell.classList.remove('is-focused'));
    });

    if (password && toggle) {
        toggle.addEventListener('click', () => {
            const showing = password.type === 'text';

            password.type = showing ? 'password' : 'text';
            toggle.setAttribute('aria-pressed', showing ? 'false' : 'true');
            toggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
            toggle.classList.remove('just-toggled');

            requestAnimationFrame(() => {
                toggle.classList.add('just-toggled');
            });

            window.setTimeout(() => {
                toggle.classList.remove('just-toggled');
            }, 360);
        });
    }

    function setVerificationStage(stage, title, message, progress, options = {}) {
        if (shell) {
            shell.dataset.loginStage = String(stage);
        }

        if (stageTitle) {
            stageTitle.textContent = title;
            stageTitle.classList.remove('stage-bump');
            void stageTitle.offsetWidth;
            stageTitle.classList.add('stage-bump');
        }

        if (stageMessage) {
            stageMessage.textContent = message;
        }

        if (stageProgress && Number.isFinite(progress)) {
            stageProgress.style.width = `${Math.max(0, Math.min(100, progress))}%`;
        }

        if (scanPercent && Number.isFinite(progress)) {
            scanPercent.textContent = `${Math.round(Math.max(0, Math.min(100, progress)))}%`;
        }

        stageSteps.forEach((step) => {
            const stepNumber = Number(step.dataset.loginStep || 0);
            const completeAll = options.completeAll === true;
            step.classList.toggle('is-active', !completeAll && stepNumber === stage);
            step.classList.toggle('is-complete', completeAll || stepNumber < stage);
        });
    }

    function wait(milliseconds) {
        return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
    }

    function setFormLocked(locked) {
        fields.forEach((input) => {
            input.readOnly = locked;
        });

        if (toggle) {
            toggle.disabled = locked;
        }

        if (submit) {
            submit.disabled = locked;
        }

        if (form) {
            if (locked) form.setAttribute('aria-busy', 'true');
            else form.removeAttribute('aria-busy');
        }
    }

    function clearInlineError() {
        const error = document.querySelector('.error-message[data-login-inline-error="true"]');
        if (error) error.remove();
    }

    function showInlineError(message, isBan = false) {
        if (!form) return;

        clearInlineError();

        const error = document.createElement('div');
        error.className = `error-message ${isBan ? 'ban' : ''} error-enter`;
        error.dataset.loginInlineError = 'true';
        error.setAttribute('role', 'alert');

        const icon = document.createElement('span');
        icon.className = 'alert-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = '!';

        const copy = document.createElement('span');
        copy.textContent = message || 'The submitted credentials could not be verified.';

        error.append(icon, copy);
        form.parentNode.insertBefore(error, form);

        window.setTimeout(() => error.classList.remove('error-enter'), 560);
    }

    function resetVerificationUi() {
        shell?.classList.remove('is-submitting', 'login-verified', 'login-rejected');
        document.body.classList.remove('login-verifying');

        setVerificationStage(
            1,
            'Preparing secure sign in...',
            'FortressAuth is ready for a protected credential verification request.',
            0
        );

        stageSteps.forEach((step) => {
            step.classList.remove('is-active', 'is-complete');
        });

        if (submit) {
            submit.classList.remove('loading', 'submitting');
            const label = submit.querySelector('span');
            if (label) label.textContent = 'Continue securely';
        }

        setFormLocked(false);
    }

    async function parseLoginResponse(response) {
        const contentType = String(response.headers.get('content-type') || '').toLowerCase();

        if (!contentType.includes('application/json')) {
            const raw = await response.text();
            throw new Error(raw && raw.length < 220
                ? raw
                : 'The authentication service returned an unexpected response.');
        }

        return response.json();
    }

    if (form && submit) {
        let submitting = false;
        let progressAnimationFrame = null;

        form.addEventListener('submit', async (event) => {
            if (submitting) return;

            event.preventDefault();
            clearInlineError();
            submitting = true;

            shell?.classList.remove('login-verified', 'login-rejected');
            shell?.classList.add('is-submitting');
            document.body.classList.add('login-verifying');

            submit.classList.add('loading', 'submitting');
            setFormLocked(true);

            const label = submit.querySelector('span');
            if (label) label.textContent = 'Verifying credentials';

            const formData = new FormData(form);
            formData.set('response_format', 'json');

            // The protected POST begins immediately. The animation below is now
            // a live presentation of the same request, not a timer that runs
            // before authentication starts.
            const requestStartedAt = performance.now();
            const minimumPresentationMs = reduceMotion ? 500 : 5200;

            const loginRequest = fetch(form.action || '/login.php', {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
            }).then(async (response) => ({
                response,
                result: await parseLoginResponse(response),
            }));

            setVerificationStage(
                1,
                'Initializing secure request...',
                'The credential package has been sent to the FortressAuth server.',
                8
            );

            if (!reduceMotion) {
                window.setTimeout(() => {
                    if (!submitting) return;
                    setVerificationStage(
                        2,
                        'Applying request protections...',
                        'Server-side input, CSRF, network, and brute-force controls are protecting this login attempt.',
                        30
                    );
                }, 1050);

                window.setTimeout(() => {
                    if (!submitting) return;
                    setVerificationStage(
                        3,
                        'Verifying administrator credentials...',
                        'FortressAuth is waiting for the server-side password verification decision.',
                        58
                    );
                }, 2550);

                const progressStartedAt = performance.now();
                const animateVerificationProgress = (now) => {
                    if (!submitting) return;

                    const elapsed = now - progressStartedAt;
                    const ratio = Math.min(1, elapsed / minimumPresentationMs);
                    const eased = 1 - Math.pow(1 - ratio, 1.7);
                    // 88% is a deliberate waiting ceiling. The scanner cannot
                    // reach 100% until the real PHP response says verified=true.
                    const progress = Math.max(8, Math.min(88, 8 + eased * 80));

                    if (stageProgress) stageProgress.style.width = `${progress}%`;
                    if (scanPercent) scanPercent.textContent = `${Math.round(progress)}%`;

                    if (submitting && progress < 88) {
                        progressAnimationFrame = requestAnimationFrame(animateVerificationProgress);
                    }
                };

                progressAnimationFrame = requestAnimationFrame(animateVerificationProgress);
            } else {
                setVerificationStage(
                    3,
                    'Verifying credentials...',
                    'Waiting for the FortressAuth server to approve or reject the submitted credentials.',
                    75
                );
            }

            try {
                const requestResult = await loginRequest;
                const elapsed = performance.now() - requestStartedAt;
                const remainingPresentation = Math.max(0, minimumPresentationMs - elapsed);

                if (remainingPresentation > 0) {
                    await wait(remainingPresentation);
                }

                if (progressAnimationFrame) {
                    cancelAnimationFrame(progressAnimationFrame);
                    progressAnimationFrame = null;
                }

                const result = requestResult.result || {};

                if (result.success === true && result.verified === true && result.redirect) {
                    shell?.classList.add('login-verified');

                    setVerificationStage(
                        4,
                        'Credentials verified',
                        result.next_step === 'personal_id_enrollment'
                            ? 'Password factor passed. Opening protected Personal ID enrollment.'
                            : (result.next_step === 'dashboard'
                                ? 'Password factor passed. Personal ID 2FA is disabled for this account; opening the dashboard.'
                                : 'Password factor passed. Continuing to registered Personal ID verification.'),
                        100,
                        { completeAll: true }
                    );

                    if (label) label.textContent = 'Credentials verified';
                    submit.classList.remove('loading');

                    // Keep the real success state visible long enough to be read.
                    await wait(reduceMotion ? 180 : 950);
                    window.location.assign(result.redirect);
                    return;
                }

                shell?.classList.add('login-rejected');
                setVerificationStage(
                    4,
                    'Access not verified',
                    result.message || 'The FortressAuth server rejected the sign-in request.',
                    100
                );

                if (label) label.textContent = 'Verification rejected';
                submit.classList.remove('loading');

                await wait(reduceMotion ? 180 : 1250);

                showInlineError(
                    result.message || 'The submitted credentials could not be verified.',
                    requestResult.response.status === 429 || result.stage === 'network_policy' || result.stage === 'bruteforce'
                );

                shell?.classList.add('login-has-error');
                window.setTimeout(() => shell?.classList.remove('login-has-error'), 560);

                submitting = false;
                resetVerificationUi();
                document.getElementById('username')?.focus();
            } catch (error) {
                if (progressAnimationFrame) {
                    cancelAnimationFrame(progressAnimationFrame);
                    progressAnimationFrame = null;
                }

                const elapsed = performance.now() - requestStartedAt;
                const remainingPresentation = Math.max(0, Math.min(1200, minimumPresentationMs - elapsed));
                if (remainingPresentation > 0) await wait(remainingPresentation);

                shell?.classList.add('login-rejected');
                setVerificationStage(
                    4,
                    'Verification service unavailable',
                    'FortressAuth could not complete the protected server verification request.',
                    100
                );

                if (label) label.textContent = 'Unable to verify';
                submit.classList.remove('loading');

                await wait(reduceMotion ? 150 : 900);

                showInlineError(error?.message || 'Unable to verify credentials. Please try again.');

                submitting = false;
                resetVerificationUi();
            }
        });
    }

    const error = document.querySelector('.error-message:not([data-login-inline-error="true"])');

    if (error) {
        error.classList.add('error-enter');
        shell?.classList.add('login-has-error');

        window.setTimeout(() => {
            error.classList.remove('error-enter');
            shell?.classList.remove('login-has-error');
        }, 560);
    }
});
