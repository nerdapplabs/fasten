// -----------------------------------------------------------------------------
// Theme toggle — dark (default) / light. Persisted in localStorage.
// Pre-hydration script in <head> sets data-theme before first paint.
// -----------------------------------------------------------------------------
(function () {
    const root = document.documentElement;
    const btn = document.querySelector('.theme-toggle');
    if (!btn) return;

    btn.addEventListener('click', () => {
        const current = root.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        try { localStorage.setItem('rivet-theme', next); } catch (e) {}
    });
})();

// -----------------------------------------------------------------------------
// Tab switching for code samples.
// -----------------------------------------------------------------------------
(function () {
    const tabs = document.querySelectorAll('.tab');
    const blocks = document.querySelectorAll('.code-block');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            tabs.forEach(t => t.classList.toggle('active', t === tab));
            blocks.forEach(b => b.classList.toggle('active', b.dataset.lang === target));
        });
    });
})();

// -----------------------------------------------------------------------------
// Subtle reveal on scroll for cards.
// -----------------------------------------------------------------------------
(function () {
    if (!('IntersectionObserver' in window)) return;

    const cards = document.querySelectorAll(
        '.pillar, .anchor, .use, .lang-card, .compare-table .row, .qs-card, .read-card'
    );
    cards.forEach(c => {
        c.style.opacity = '0';
        c.style.transform = 'translateY(8px)';
        c.style.transition = 'opacity 380ms ease, transform 380ms ease';
    });

    const io = new IntersectionObserver((entries) => {
        entries.forEach((e, i) => {
            if (e.isIntersecting) {
                setTimeout(() => {
                    e.target.style.opacity = '1';
                    e.target.style.transform = 'translateY(0)';
                }, i * 30);
                io.unobserve(e.target);
            }
        });
    }, { threshold: 0.12 });

    cards.forEach(c => io.observe(c));
})();
