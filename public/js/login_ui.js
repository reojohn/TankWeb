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
    const aiToast = document.getElementById('ai-login-toast');
    const aiToastTitle = document.getElementById('ai-login-toast-title');
    const aiToastMessage = document.getElementById('ai-login-toast-message');
    const aiToastClose = aiToast?.querySelector('.ai-login-toast-close');
    let aiToastTimer = null;

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

    function publicFailureCopy(result = {}, responseStatus = 0) {
        const stage = String(result.stage || '');

        if (stage === 'password' || stage === 'credential_format') {
            return {
                title: 'Access not verified',
                message: 'The submitted credentials could not be verified.'
            };
        }

        if (stage === 'csrf' || stage === 'request_security' || stage === 'network_policy' || stage === 'bruteforce' || responseStatus === 403 || responseStatus === 429) {
            return {
                title: 'Sign-in activity flagged',
                message: 'This access attempt was not accepted.'
            };
        }

        return {
            title: 'Access not verified',
            message: 'The sign-in attempt could not be completed.'
        };
    }

    function showAiDefenseToast(title, message) {
        if (!aiToast) return;

        if (aiToastTimer) {
            window.clearTimeout(aiToastTimer);
            aiToastTimer = null;
        }

        if (aiToastTitle) aiToastTitle.textContent = title || 'Access not verified';
        if (aiToastMessage) aiToastMessage.textContent = message || 'This sign-in attempt was not accepted.';

        aiToast.hidden = false;
        aiToast.classList.remove('is-visible', 'is-leaving');
        void aiToast.offsetWidth;
        aiToast.classList.add('is-visible');

        aiToastTimer = window.setTimeout(() => {
            aiToast.classList.add('is-leaving');
            window.setTimeout(() => {
                aiToast.classList.remove('is-visible', 'is-leaving');
                aiToast.hidden = true;
            }, reduceMotion ? 0 : 320);
        }, 6200);
    }

    aiToastClose?.addEventListener('click', () => {
        if (!aiToast) return;
        if (aiToastTimer) window.clearTimeout(aiToastTimer);
        aiToastTimer = null;
        aiToast.classList.add('is-leaving');
        window.setTimeout(() => {
            aiToast.classList.remove('is-visible', 'is-leaving');
            aiToast.hidden = true;
        }, reduceMotion ? 0 : 260);
    });

    function resetVerificationUi() {
        shell?.classList.remove('is-submitting', 'login-verified', 'login-rejected');
        document.body.classList.remove('login-verifying');

        setVerificationStage(
            1,
            'Preparing sign in...',
            'FortressAuth is ready to evaluate your access request.',
            0
        );

        stageSteps.forEach((step) => {
            step.classList.remove('is-active', 'is-complete');
        });

        if (submit) {
            submit.classList.remove('loading', 'submitting');
            const label = submit.querySelector('.login-button-label') || submit.querySelector('span');
            if (label) label.textContent = 'Login';
            submit.setAttribute('aria-label', 'Login');
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

            if (aiToast && !aiToast.hidden) {
                if (aiToastTimer) window.clearTimeout(aiToastTimer);
                aiToastTimer = null;
                aiToast.classList.remove('is-visible', 'is-leaving');
                aiToast.hidden = true;
            }

            submitting = true;

            shell?.classList.remove('login-verified', 'login-rejected');
            shell?.classList.add('is-submitting');
            document.body.classList.add('login-verifying');

            setFormLocked(true);

            const label = submit.querySelector('.login-button-label') || submit.querySelector('span');
            if (label) label.textContent = 'Login';
            submit.setAttribute('aria-label', 'Login');

            const formData = new FormData(form);
            formData.set('response_format', 'json');

            // The protected POST begins immediately. The animation below is now
            // a live presentation of the same request, not a timer that runs
            // before authentication starts.
            const requestStartedAt = performance.now();
            const minimumPresentationMs = reduceMotion ? 180 : 650;

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
                'Submitting sign-in request...',
                'Your access request is being evaluated.',
                8
            );

            if (!reduceMotion) {
                window.setTimeout(() => {
                    if (!submitting) return;
                    setVerificationStage(
                        2,
                        'Reviewing access context...',
                        'FortressAuth is assessing the current sign-in request.',
                        30
                    );
                }, 140);

                window.setTimeout(() => {
                    if (!submitting) return;
                    setVerificationStage(
                        3,
                        'Confirming administrator access...',
                        'Waiting for the final access decision.',
                        58
                    );
                }, 330);

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
                    'Confirming access...',
                    'Waiting for the final access decision.',
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
                        'Access verified',
                        result.next_step === 'dashboard'
                            ? 'Access approved. Opening your administrative workspace.'
                            : 'Access approved. Continuing to the next authorized step.',
                        100,
                        { completeAll: true }
                    );

                    if (label) label.textContent = 'Login';
                    submit.setAttribute('aria-label', 'Login');

                    // Keep the real success state visible long enough to be read.
                    await wait(reduceMotion ? 90 : 300);
                    window.location.assign(result.redirect);
                    return;
                }

                const publicFailure = publicFailureCopy(result, requestResult.response.status);

                shell?.classList.add('login-rejected');
                setVerificationStage(
                    4,
                    publicFailure.title,
                    publicFailure.message,
                    100
                );

                if (label) label.textContent = 'Login';
                submit.setAttribute('aria-label', 'Login');

                showAiDefenseToast(publicFailure.title, publicFailure.message);

                await wait(reduceMotion ? 180 : 1250);

                showInlineError(
                    publicFailure.message,
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
                    'Unable to complete sign in',
                    'The access request could not be completed at this time.',
                    100
                );

                if (label) label.textContent = 'Login';
                submit.setAttribute('aria-label', 'Login');

                await wait(reduceMotion ? 150 : 900);

                const unavailableCopy = {
                    title: 'Sign-in activity flagged',
                    message: 'This access attempt could not be completed.'
                };

                showAiDefenseToast(unavailableCopy.title, unavailableCopy.message);
                showInlineError(unavailableCopy.message);

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
