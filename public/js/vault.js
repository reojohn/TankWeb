(() => {
    'use strict';

    const timeoutIds = new Set();

    const later = (callback, delay) => {
        const id = window.setTimeout(() => {
            timeoutIds.delete(id);
            callback();
        }, delay);
        timeoutIds.add(id);
        return id;
    };

    const destroy = () => {
        timeoutIds.forEach((id) => window.clearTimeout(id));
        timeoutIds.clear();
    };

    const init = () => {
        destroy();

    const body = document.body;
    const label = document.getElementById('vault-stage-label');
    const progressValue = document.getElementById('vault-progress-value');
    const progressBar = document.getElementById('vault-progress-bar');
    const visualStatus = document.getElementById('vault-visual-status');
    const steps = Array.from(document.querySelectorAll('[data-step]'));
    const copyButton = document.getElementById('vault-copy-flag');
    const flag = document.getElementById('vault-flag');

    if (!body || !label || !progressValue || !progressBar || !visualStatus) return;

    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    const stages = [
        { delay: 450, stage: 'perimeter', progress: 18, step: 1, label: 'Validating protected perimeter', visual: 'Scanning perimeter' },
        { delay: 1500, stage: 'session', progress: 42, step: 2, label: 'Confirming verified administrator session', visual: 'Session evidence confirmed' },
        { delay: 2850, stage: 'unlock', progress: 68, step: 3, label: 'Releasing crown-jewel vault locks', visual: 'Lock sequence releasing' },
        { delay: 4300, stage: 'open', progress: 88, step: 4, label: 'Opening protected objective chamber', visual: 'Vault opening' },
        { delay: 5600, stage: 'reward', progress: 100, step: 4, label: 'Penetration-test objective captured', visual: 'Crown jewel exposed' },
    ];

    function markSteps(current, completed = false) {
        steps.forEach((item) => {
            const number = Number(item.dataset.step || 0);
            item.classList.toggle('active', number === current && !completed);
            item.classList.toggle('done', number < current || (completed && number <= current));
        });
    }

    function applyStage(item, completed = false) {
        body.dataset.vaultStage = item.stage;
        label.textContent = item.label;
        progressValue.textContent = `${item.progress}%`;
        visualStatus.textContent = item.visual;
        markSteps(item.step, completed);

        if (item.stage === 'unlock') {
            const lockIcon = document.querySelector('.vault-lock-hub i');
            lockIcon?.classList.remove('fa-lock');
            lockIcon?.classList.add('fa-lock-open');
        }
    }

    if (reducedMotion) {
        applyStage(stages[stages.length - 1], true);
    } else {
        stages.forEach((item, index) => {
            later(() => {
                applyStage(item, index === stages.length - 1);
                if (item.stage === 'reward') {
                    document.getElementById('vault-reward')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }, item.delay);
        });
    }

    if (copyButton && flag) {
        copyButton.addEventListener('click', async () => {
            const text = flag.textContent || '';
            const labelNode = copyButton.querySelector('span');
            const icon = copyButton.querySelector('i');

            try {
                if (navigator.clipboard?.writeText) {
                    await navigator.clipboard.writeText(text);
                } else {
                    const selection = window.getSelection();
                    const range = document.createRange();
                    range.selectNodeContents(flag);
                    selection?.removeAllRanges();
                    selection?.addRange(range);
                    document.execCommand('copy');
                    selection?.removeAllRanges();
                }

                copyButton.classList.add('copied');
                if (labelNode) labelNode.textContent = 'Flag copied';
                icon?.classList.remove('fa-copy');
                icon?.classList.add('fa-circle-check');

                later(() => {
                    copyButton.classList.remove('copied');
                    if (labelNode) labelNode.textContent = 'Copy flag';
                    icon?.classList.remove('fa-circle-check');
                    icon?.classList.add('fa-copy');
                }, 1800);
            } catch (_) {
                if (labelNode) labelNode.textContent = 'Select flag manually';
            }
        });
    }

    };

    window.FortressVault = { init, destroy };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }
})();
