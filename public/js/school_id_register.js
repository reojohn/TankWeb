document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('start-scanner');
    const status = document.getElementById('scanner-status');
    const statusTitle = document.getElementById('scanner-status-title');
    const statusCard = document.getElementById('scanner-status-card');
    const cameraState = document.getElementById('camera-state');
    const scannerStage = document.getElementById('scanner-stage');
    const placeholder = document.getElementById('scanner-placeholder');
    const verificationCard = document.getElementById('verification-card');

    if (!button || !status) {
        return;
    }

    let scanner = null;
    let scanCompleted = false;

    let audioContext = null;

    const getAudioContext = async () => {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return null;
        if (!audioContext) audioContext = new AudioCtx();
        if (audioContext.state === 'suspended') {
            try { await audioContext.resume(); } catch (_) {}
        }
        return audioContext;
    };

    const playScanSound = async (kind) => {
        const ctx = await getAudioContext();
        if (!ctx) return;

        const now = ctx.currentTime;
        const master = ctx.createGain();
        master.gain.setValueAtTime(0.0001, now);
        master.gain.exponentialRampToValueAtTime(0.16, now + 0.012);
        master.gain.exponentialRampToValueAtTime(0.0001, now + (kind === 'success' ? 0.42 : 0.34));
        master.connect(ctx.destination);

        const notes = kind === 'success'
            ? [{ f: 660, t: 0, d: 0.11 }, { f: 880, t: 0.12, d: 0.13 }, { f: 1175, t: 0.25, d: 0.15 }]
            : [{ f: 220, t: 0, d: 0.13 }, { f: 165, t: 0.14, d: 0.17 }];

        notes.forEach(({ f, t, d }) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = kind === 'success' ? 'sine' : 'triangle';
            osc.frequency.setValueAtTime(f, now + t);
            gain.gain.setValueAtTime(0.0001, now + t);
            gain.gain.exponentialRampToValueAtTime(kind === 'success' ? 0.38 : 0.26, now + t + 0.01);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + t + d);
            osc.connect(gain);
            gain.connect(master);
            osc.start(now + t);
            osc.stop(now + t + d + 0.03);
        });
    };

    const setStatus = (type, title, message) => {
        if (statusCard) {
            statusCard.classList.remove('neutral', 'working', 'success', 'error');
            statusCard.classList.add(type, 'status-changed');

            window.setTimeout(() => {
                statusCard.classList.remove('status-changed');
            }, 360);
        }

        if (statusTitle) {
            statusTitle.textContent = title;
        }

        status.textContent = message;
    };

    const setCameraState = (active, label) => {
        if (!cameraState) {
            return;
        }

        cameraState.classList.toggle('active', active);
        cameraState.classList.toggle('busy', !active && ['Registering', 'Registered'].includes(label));

        const textNode = [...cameraState.childNodes].find((node) => node.nodeType === Node.TEXT_NODE);

        if (textNode) {
            textNode.textContent = ` ${label}`;
        }
    };

    button.addEventListener('click', async () => {
        if (scanner) {
            try {
                scanner.clear();
            } catch (error) {
                console.warn('Scanner clear warning:', error);
            }
        }

        scanCompleted = false;
        await getAudioContext();
        button.disabled = true;
        button.classList.add('loading');
        verificationCard?.classList.remove('verification-error', 'verification-success');
        verificationCard?.classList.add('scanner-live');

        setStatus('working', 'Requesting camera access', 'Allow camera access if your browser asks for permission.');

        try {
            if (typeof Html5Qrcode === 'undefined') {
                throw new Error('QR scanner library failed to load.');
            }

            const cameras = await Html5Qrcode.getCameras();

            if (!cameras || cameras.length === 0) {
                throw new Error('No webcam was detected.');
            }

            scanner = new Html5Qrcode('reader', {
                formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE]
            });

            placeholder?.classList.add('is-hidden');
            scannerStage?.classList.remove('is-error', 'is-success', 'is-processing');
            scannerStage?.classList.add('is-scanning');

            setCameraState(true, 'Camera active');
            setStatus('working', 'Scanning Personal ID', 'Hold your Personal ID QR code inside the frame to enroll it.');

            const targetSize = Math.max(205, Math.min(285, Math.floor((scannerStage?.clientWidth || 520) * 0.48)));

            await scanner.start(
                cameras[0].id,
                {
                    fps: 12,
                    qrbox: {
                        width: targetSize,
                        height: targetSize
                    },
                    aspectRatio: 1.333333
                },
                async (decodedText) => {
                    if (scanCompleted) {
                        return;
                    }

                    scanCompleted = true;
                    setStatus('working', 'QR detected', 'Securing and registering this Personal ID to your account...');

                    scannerStage?.classList.remove('is-scanning');
                    scannerStage?.classList.add('is-processing');

                    try {
                        await scanner.stop();
                    } catch (error) {
                        console.warn('Scanner stop warning:', error);
                    }

                    setCameraState(false, 'Registering');
                    await registerSchoolId(decodedText);
                },
                () => {
                    // Normal frames without a QR code are intentionally ignored.
                }
            );

            button.classList.remove('loading');
            button.querySelector('span').textContent = 'Scanner active';

        } catch (error) {
            console.error(error);

            scannerStage?.classList.remove('is-scanning', 'is-processing');
            scannerStage?.classList.add('is-error');
            placeholder?.classList.remove('is-hidden');

            verificationCard?.classList.remove('scanner-live');
            verificationCard?.classList.add('verification-error');

            setCameraState(false, 'Camera off');
            setStatus('error', 'Camera unavailable', error.message || 'Unable to start the camera.');

            button.disabled = false;
            button.classList.remove('loading');
            button.querySelector('span').textContent = 'Try scanner again';

            window.setTimeout(() => {
                verificationCard?.classList.remove('verification-error');
            }, 620);
        }
    });

    async function registerSchoolId(qrValue) {
        try {
            const csrfElement = document.querySelector('meta[name="csrf-token"]');
            const csrfToken = csrfElement ? csrfElement.getAttribute('content') : '';

            const response = await fetch('/school_id_register_finish.php', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ qr_value: qrValue })
            });

            const result = await response.json();

            if (!response.ok || result.success !== true) {
                throw new Error(result.error || 'Personal ID registration failed.');
            }

            scannerStage?.classList.remove('is-processing');
            scannerStage?.classList.add('is-success');

            verificationCard?.classList.remove('scanner-live', 'verification-error');
            verificationCard?.classList.add('verification-success');

            setCameraState(false, 'Registered');
            setStatus('success', 'Personal ID registered', 'Your Personal ID is now linked to this account and ready for verification.');
            playScanSound('success');
            button.classList.add('is-hidden');

            if (result.redirect) {
                window.setTimeout(() => {
                    window.location.href = result.redirect;
                }, 900);
            }

        } catch (error) {
            console.error(error);

            scannerStage?.classList.remove('is-processing', 'is-success');
            scannerStage?.classList.add('is-error');

            verificationCard?.classList.remove('scanner-live', 'verification-success');
            verificationCard?.classList.add('verification-error');

            setCameraState(false, 'Registration failed');
            setStatus('error', 'Personal ID not registered', error.message || 'Unable to register Personal ID.');
            playScanSound('error');

            scanCompleted = false;
            button.disabled = false;
            button.classList.remove('loading');
            button.querySelector('span').textContent = 'Scan Personal ID again';
            placeholder?.classList.remove('is-hidden');

            window.setTimeout(() => {
                scannerStage?.classList.remove('is-error');
                verificationCard?.classList.remove('verification-error');
            }, 850);
        }
    }
});
