document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const shell = document.querySelector('.auth-shell');
  const form = document.getElementById('honeypot-login-form');
  const username = document.getElementById('admin_user');
  const password = document.getElementById('admin_pass');
  const toggle = document.getElementById('honeypot-password-toggle');
  const submit = document.getElementById('honeypot-submit');

  const stageTitle = document.getElementById('honeypot-stage-title');
  const stageMessage = document.getElementById('honeypot-stage-message');
  const stageProgress = document.getElementById('honeypot-stage-progress-bar');
  const scanPercent = document.getElementById('honeypot-scan-percent');
  const stageSteps = Array.from(document.querySelectorAll('[data-honeypot-step]'));

  const reduceMotion =
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const setStage = (stage, title, message, progress) => {
    if (stageTitle) {
      stageTitle.textContent = title;
      stageTitle.classList.remove('stage-bump');
      void stageTitle.offsetWidth;
      stageTitle.classList.add('stage-bump');
    }

    if (stageMessage) {
      stageMessage.textContent = message;
    }

    if (stageProgress) {
      stageProgress.style.width = `${progress}%`;
    }

    if (scanPercent) {
      scanPercent.textContent = `${Math.round(progress)}%`;
    }

    stageSteps.forEach((step) => {
      const stepNumber = Number(step.dataset.honeypotStep || 0);
      step.classList.toggle('is-active', stepNumber === stage);
      step.classList.toggle('is-complete', stepNumber < stage);
    });
  };

  if (toggle && password) {
    toggle.addEventListener('click', () => {
      const showing = password.type === 'text';

      password.type = showing ? 'password' : 'text';
      toggle.setAttribute('aria-pressed', showing ? 'false' : 'true');
      toggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');

      toggle.classList.remove('just-toggled');
      void toggle.offsetWidth;
      toggle.classList.add('just-toggled');

      window.setTimeout(() => toggle.classList.remove('just-toggled'), 220);
    });
  }

  const error = document.querySelector('.error-message');
  if (error) {
    error.classList.add('error-enter');
    shell?.classList.add('login-has-error');

    window.setTimeout(() => {
      error.classList.remove('error-enter');
      shell?.classList.remove('login-has-error');
    }, 560);
  }

  if (!form || !submit) {
    return;
  }

  let submitting = false;

  form.addEventListener('submit', (event) => {
    if (submitting) {
      event.preventDefault();
      return;
    }

    event.preventDefault();
    submitting = true;

    shell?.classList.add('is-submitting');
    document.body.classList.add('login-verifying');

    submit.disabled = true;
    submit.classList.add('loading', 'submitting');
    form.setAttribute('aria-busy', 'true');

    if (username) username.readOnly = true;
    if (password) password.readOnly = true;
    if (toggle) toggle.disabled = true;

    const label = submit.querySelector('span');
    if (label) {
      label.textContent = 'Verifying credentials';
    }

    if (reduceMotion) {
      setStage(
        4,
        'Sending secure request...',
        'Submitting the administrator access request for verification.',
        100
      );

      window.setTimeout(() => form.submit(), 100);
      return;
    }

    const stages = [
      {
        delay: 0,
        stage: 1,
        progress: 18,
        title: 'Preparing secure sign in...',
        message: 'Initializing the FortressAuth protected access workflow.',
      },
      {
        delay: 340,
        stage: 2,
        progress: 44,
        title: 'Securing credentials...',
        message: 'Preparing the submitted administrator credentials for verification.',
      },
      {
        delay: 700,
        stage: 3,
        progress: 72,
        title: 'Fortress defenses standing by...',
        message: 'Security monitoring and access defenses are evaluating this request.',
      },
      {
        delay: 1050,
        stage: 4,
        progress: 100,
        title: 'Verifying administrator access...',
        message: 'Completing the protected administrator sign-in request.',
      },
    ];

    stages.forEach((item) => {
      window.setTimeout(() => {
        if (!submitting) return;
        setStage(item.stage, item.title, item.message, item.progress);
      }, item.delay);
    });

    window.setTimeout(() => {
      form.submit();
    }, 1320);
  });
});
