document.addEventListener('DOMContentLoaded', () => {
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const shells = document.querySelectorAll('.auth-shell, .verify-shell');

    document.body.classList.add('ui-ready');

    if (reduceMotion) {
        return;
    }

    shells.forEach((shell) => {
        let frame = null;

        const updateTilt = (event) => {
            const rect = shell.getBoundingClientRect();
            const x = (event.clientX - rect.left) / rect.width;
            const y = (event.clientY - rect.top) / rect.height;

            if (frame) {
                cancelAnimationFrame(frame);
            }

            frame = requestAnimationFrame(() => {
                const tiltX = (x - 0.5) * 0.9;
                const tiltY = (0.5 - y) * 0.7;

                shell.style.setProperty('--tilt-x', `${tiltX.toFixed(3)}deg`);
                shell.style.setProperty('--tilt-y', `${tiltY.toFixed(3)}deg`);
                shell.style.setProperty('--pointer-x', `${(x * 100).toFixed(2)}%`);
                shell.style.setProperty('--pointer-y', `${(y * 100).toFixed(2)}%`);
            });
        };

        shell.addEventListener('pointermove', updateTilt);

        shell.addEventListener('pointerleave', () => {
            if (frame) {
                cancelAnimationFrame(frame);
            }

            shell.style.setProperty('--tilt-x', '0deg');
            shell.style.setProperty('--tilt-y', '0deg');
            shell.style.setProperty('--pointer-x', '50%');
            shell.style.setProperty('--pointer-y', '50%');
        });
    });
});
