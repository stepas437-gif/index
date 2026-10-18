const NOMINATION_LABELS = {
    best_track: 'Лучший трек',
    best_producer: 'Лучший продюсер',
    best_artist: 'Лучший артист'
};

const STREAMER_SOCIALS = [
    {
        href: 'https://t.me/CURSED_DEVIL',
        label: 'Telegram',
        icon: '<path d="M20.665 3.717 17.735 17.54c-.221.976-.799 1.219-1.62.759l-4.48-3.302-2.161 2.08c-.239.239-.439.439-.9.439l.322-4.565 8.307-7.506c.361-.322-.078-.5-.561-.178L6.37 10.733l-4.41-1.379c-.959-.3-.976-.959.2-1.419L19.4 1.29c.799-.299 1.498.178 1.265 2.427Z" />'
    },
    {
        href: 'https://t.me/curseddevil66',
        label: 'Канал',
        icon: '<path d="M3 5h18v4H3V5Zm0 6h12v4H3v-4Zm0 6h8v2H3v-2Zm14-6 4 3-4 3v-6Z" />'
    },
    {
        href: 'https://t.me/tribute/app?startapp=sqoZ',
        label: 'Поддержка',
        icon: '<path d="m12 2 3.09 6.26 6.91 1-5 4.87L18.18 21 12 17.77 5.82 21 7 14.13 2 9.26l6.91-1L12 2Z" />'
    },
    {
        href: 'https://vk.com/cursed_devil666',
        label: 'VK',
        icon: '<path d="M3 6.5c.17 8.13 4.24 13.02 11.38 13.02h.41V14.9c2.6.27 4.56 2.17 5.35 4.62H24c-1.01-3.68-3.65-5.71-5.3-6.49 1.65-.95 3.95-3.27 4.5-6.53H20c-.72 2.65-2.83 4.97-5.21 5.19V6.5h-3.1v9.07C9.28 14.97 6.2 12.44 6.07 6.5H3Z" />'
    },
    {
        href: 'https://www.twitch.tv/curseddevillll',
        label: 'Twitch',
        icon: '<path d="M4 3 3 8v12h4v3l3-3h4l7-7V3H4Zm15 9-4 4h-4l-3 3v-3H5V5h14v7Zm-7-5h2v5h-2V7Zm4 0h2v5h-2V7Z" />'
    }
];

const REVEAL_SELECTOR = [
    '.topbar',
    '.page-head > *',
    '.home-hero > *',
    '.glass-panel',
    '.panel',
    '.track-card',
    '.mini-card',
    '.nomination-card',
    '.podium-item',
    '.leaderboard',
    '.profile-stat',
    '.site-footer',
    '.footer-links a',
    '.home-step',
    '.home-metric',
    '.audio-comment-board',
    '.message.visible'
].join(', ');

let revealObserver = null;
let pageTransitionTimer = null;

function animationsReduced() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function ensureRevealObserver() {
    if (revealObserver || animationsReduced() || typeof IntersectionObserver === 'undefined') {
        return revealObserver;
    }

    revealObserver = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }

                entry.target.classList.add('is-visible');
                revealObserver.unobserve(entry.target);
            });
        },
        {
            rootMargin: '0px 0px -8% 0px',
            threshold: 0.08
        }
    );

    return revealObserver;
}

function applyRevealAnimations(root = document) {
    if (!root || animationsReduced()) {
        return;
    }

    const targets = [];
    if (root.matches && root.matches(REVEAL_SELECTOR)) {
        targets.push(root);
    }

    if (root.querySelectorAll) {
        targets.push(...root.querySelectorAll(REVEAL_SELECTOR));
    }

    if (!targets.length) {
        return;
    }

    const observer = ensureRevealObserver();

    [...new Set(targets)].forEach((element, index) => {
        if (element.dataset.motionReady === '1') {
            return;
        }

        element.dataset.motionReady = '1';
        element.style.setProperty('--reveal-delay', `${Math.min(index * 36, 180)}ms`);
        element.classList.add('reveal-item');

        if (observer) {
            observer.observe(element);
            return;
        }

        requestAnimationFrame(() => {
            element.classList.add('is-visible');
        });
    });
}

function ensureTransitionOverlay() {
    let overlay = document.querySelector('.page-transition-overlay');
    if (overlay) {
        return overlay;
    }

    overlay = document.createElement('div');
    overlay.className = 'page-transition-overlay';
    overlay.setAttribute('aria-hidden', 'true');
    document.body.appendChild(overlay);
    return overlay;
}

function startPageTransition(href) {
    if (!href || pageTransitionTimer) {
        return;
    }

    ensureTransitionOverlay().classList.add('is-active');
    document.body.classList.add('is-page-leaving');
    pageTransitionTimer = window.setTimeout(() => {
        window.location.href = href;
    }, 180);
}

function bindPageTransitions(root = document) {
    if (!root) {
        return;
    }

    const selector = 'a[href]';
    const links =
        root.matches && root.matches('a[href]')
            ? [root]
            : Array.from(root.querySelectorAll ? root.querySelectorAll(selector) : []);

    links.forEach((link) => {
        if (!link.closest('.topbar, .site-footer, .user-menu-panel')) {
            return;
        }

        if (link.dataset.pageTransitionBound === '1') {
            return;
        }

        link.dataset.pageTransitionBound = '1';
        link.addEventListener('click', (event) => {
            if (
                event.defaultPrevented ||
                event.button !== 0 ||
                event.metaKey ||
                event.ctrlKey ||
                event.shiftKey ||
                event.altKey ||
                link.target === '_blank' ||
                link.hasAttribute('download')
            ) {
                return;
            }

            const url = new URL(link.href, window.location.href);
            if (url.origin !== window.location.origin) {
                return;
            }

            if (
                url.pathname === window.location.pathname &&
                url.search === window.location.search &&
                !url.hash
            ) {
                return;
            }

            event.preventDefault();
            startPageTransition(url.href);
        });
    });
}

async function apiFetch(url, options = {}) {
    const response = await fetch(url, options);
    let payload = null;

    try {
        payload = await response.json();
    } catch (_error) {
        payload = null;
    }

    if (!response.ok) {
        throw new Error(payload && payload.error ? payload.error : `Запрос не выполнен (HTTP ${response.status}).`);
    }

    return payload;
}

function showMessage(element, type, text, extraHtml = '') {
    element.className = `message ${type} visible`;
    element.innerHTML = extraHtml ? `${text}<div>${extraHtml}</div>` : text;
    applyRevealAnimations(element);
}

function hideMessage(element) {
    element.className = 'message';
    element.textContent = '';
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function statusLabel(status) {
    return status === 'evaluated' ? 'Разобран' : 'На разборе';
}

function formatDate(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) {
        return '';
    }

    return new Intl.DateTimeFormat('ru-RU', {
        dateStyle: 'medium',
        timeStyle: 'short'
    }).format(date);
}

function formatTimestamp(seconds) {
    const totalSeconds = Math.max(0, Math.round(Number(seconds) || 0));
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;

    if (hours > 0) {
        return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }

    return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function roleLabel(role) {
    if (role === 'streamer') return 'Стример';
    if (role === 'viewer') return 'Слушатель';
    return 'Автор';
}

function nominationLabel(key) {
    return NOMINATION_LABELS[key] || '';
}

function isNominationSelected(value) {
    return value === true || value === 1 || value === '1' || value === 'true';
}

function trackNominationKeys(track) {
    if (!track) {
        return [];
    }

    return Object.keys(NOMINATION_LABELS).filter((key) => isNominationSelected(track[key]));
}

function userHomePath(user) {
    if (!user) {
        return '/login.html';
    }

    if (!user.verified) {
        return '/index.html';
    }

    if (user.role === 'streamer') {
        return '/admin.html';
    }

    if (user.role === 'author') {
        return '/upload.html';
    }

    return '/results.html';
}

async function getSession() {
    const payload = await apiFetch('/api/session');
    return payload.user;
}

async function logout() {
    await apiFetch('/api/logout', {
        method: 'POST'
    });
    startPageTransition('/login.html');
}

function avatarUrl(path) {
    return path ? `/uploads/${encodeURIComponent(path)}` : '/default-avatar.svg';
}

function ensureFavicon() {
    if (document.head.querySelector('link[rel="icon"]')) {
        return;
    }

    const link = document.createElement('link');
    link.rel = 'icon';
    link.type = 'image/png';
    link.href = '/favicon.png';
    document.head.appendChild(link);
}

function bindBrandLinks(root = document) {
    if (!root || !root.querySelectorAll) {
        return;
    }

    root.querySelectorAll('.brand').forEach((brand) => {
        if (brand.dataset.brandLinkBound === '1') {
            return;
        }

        brand.dataset.brandLinkBound = '1';
        brand.setAttribute('role', 'link');
        brand.setAttribute('tabindex', '0');

        const openHome = () => startPageTransition('/index.html');

        brand.addEventListener('click', (event) => {
            if (event.target.closest('a, button, input, textarea, select, summary')) {
                return;
            }

            openHome();
        });

        brand.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') {
                return;
            }

            event.preventDefault();
            openHome();
        });
    });
}

function renderFooterSocialLinks() {
    return STREAMER_SOCIALS.map(
        (item) => `
            <a class="footer-social-link" href="${item.href}" target="_blank" rel="noreferrer" aria-label="${item.label}" title="${item.label}">
                <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
                    ${item.icon}
                </svg>
            </a>
        `
    ).join('');
}

function bindResendVerificationButton(buttonId, bannerElement) {
    const resendButton = document.getElementById(buttonId);
    if (!resendButton || !bannerElement) {
        return;
    }

    resendButton.addEventListener('click', async () => {
        try {
            const payload = await apiFetch('/api/resend-verification', { method: 'POST' });
            const extra = payload.previewUrl
                ? `<a href="${payload.previewUrl}" target="_blank" rel="noreferrer">Открыть ссылку подтверждения</a>`
                : '';
            showMessage(bannerElement, 'info', payload.message, extra);
        } catch (error) {
            showMessage(bannerElement, 'error', error.message);
        }
    });
}

function showVerificationBanner(bannerElement, text = 'Подтверди почту.') {
    if (!bannerElement) {
        return;
    }

    showMessage(
        bannerElement,
        'info',
        text,
        '<button class="button ghost" id="resend-mail-btn" type="button">Отправить письмо ещё раз</button>'
    );
    bindResendVerificationButton('resend-mail-btn', bannerElement);
}

function attachUserMenuBehavior(detailsElement) {
    if (!detailsElement || detailsElement.dataset.userMenuBound === '1') {
        return;
    }

    detailsElement.dataset.userMenuBound = '1';
    const trigger = detailsElement.querySelector('.user-menu-trigger');
    const closeDelayMs = 220;

    function syncExpandedState(isOpen) {
        if (!trigger) {
            return;
        }

        trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }

    function openMenu() {
        if (detailsElement.classList.contains('is-open')) {
            return;
        }

        window.clearTimeout(detailsElement.userMenuTimer);
        detailsElement.open = true;
        detailsElement.classList.remove('is-closing');
        syncExpandedState(true);

        requestAnimationFrame(() => {
            detailsElement.classList.add('is-opening');

            requestAnimationFrame(() => {
                detailsElement.classList.add('is-open');
                detailsElement.classList.remove('is-opening');
            });
        });
    }

    function closeMenu({ focusTrigger = false } = {}) {
        const menuVisible =
            detailsElement.open ||
            detailsElement.classList.contains('is-open') ||
            detailsElement.classList.contains('is-opening');

        if (!menuVisible) {
            syncExpandedState(false);
            if (focusTrigger && trigger) {
                trigger.focus();
            }
            return;
        }

        window.clearTimeout(detailsElement.userMenuTimer);
        detailsElement.classList.remove('is-open', 'is-opening');
        detailsElement.classList.add('is-closing');
        syncExpandedState(false);

        const finishClose = () => {
            detailsElement.open = false;
            detailsElement.classList.remove('is-closing');

            if (focusTrigger && trigger) {
                trigger.focus();
            }
        };

        if (animationsReduced()) {
            finishClose();
            return;
        }

        detailsElement.userMenuTimer = window.setTimeout(finishClose, closeDelayMs);
    }

    if (trigger) {
        trigger.setAttribute('aria-haspopup', 'menu');
        trigger.setAttribute('aria-expanded', 'false');

        trigger.addEventListener('click', (event) => {
            event.preventDefault();

            if (detailsElement.classList.contains('is-open') || detailsElement.classList.contains('is-opening')) {
                closeMenu();
                return;
            }

            openMenu();
        });
    }

    document.addEventListener('click', (event) => {
        const menuVisible =
            detailsElement.open ||
            detailsElement.classList.contains('is-open') ||
            detailsElement.classList.contains('is-opening');

        if (!menuVisible) {
            return;
        }

        if (!detailsElement.contains(event.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') {
            return;
        }

        closeMenu({ focusTrigger: true });
    });
}

function topbarLinksForUser(user) {
    if (user && !user.verified) {
        return [{ href: '/index.html', label: 'Главная' }];
    }

    return [
        { href: '/index.html', label: 'Главная', roles: ['author', 'viewer', 'streamer'] },
        { href: '/upload.html', label: 'Загрузка', roles: ['author', 'streamer'] },
        { href: '/admin.html', label: 'Разбор', roles: ['streamer'] },
        { href: '/results.html', label: 'Таблица', roles: ['author', 'viewer', 'streamer'] }
    ].filter((item) => !user || item.roles.includes(user.role));
}

function footerLinksForUser(user) {
    if (user && !user.verified) {
        return [{ href: '/index.html', label: 'Главная' }];
    }

    const links = [{ href: '/index.html', label: 'Главная' }, { href: '/results.html', label: 'Таблица' }];

    if (user && (user.role === 'author' || user.role === 'streamer')) {
        links.push({ href: '/upload.html', label: 'Загрузка' });
    }

    if (user && user.role === 'streamer') {
        links.push({ href: '/admin.html', label: 'Разбор' });
    }

    if (user) {
        links.push({ href: '/profile.html', label: 'Профиль' });
    } else {
        links.push({ href: '/login.html', label: 'Вход' });
    }

    return links;
}

function renderSiteFooter(user) {
    const footer = document.querySelector('.site-footer');
    if (!footer) {
        return;
    }

    const year = new Date().getFullYear();
    footer.innerHTML = `
        <div class="footer-grid">
            <div class="footer-brand">
                <span class="eyebrow">Навигация по сайту</span>
                <h3>CHUPEP</h3>
            </div>
            <div class="footer-side">
                <nav class="footer-links" aria-label="Нижняя навигация">
                    ${footerLinksForUser(user)
                        .map((item) => `<a href="${item.href}">${item.label}</a>`)
                        .join('')}
                </nav>
                <div class="footer-social" aria-label="Соцсети стримера">
                    ${renderFooterSocialLinks()}
                </div>
            </div>
        </div>
        <div class="footer-bottom">
            <span>&copy; ${year} CHUPEP</span>
        </div>
    `;

    bindPageTransitions(footer);
    applyRevealAnimations(footer);
}

function setupTopbar(activePath, user) {
    const nav = document.querySelector('[data-nav]');
    const actions = document.querySelector('[data-actions]');

    if (!nav || !actions) {
        return;
    }

    const links = topbarLinksForUser(user);

    nav.innerHTML = links
        .map(
            (item) =>
                `<a href="${item.href}" class="${activePath === item.href ? 'active' : ''}">${item.label}</a>`
        )
        .join('');

    actions.innerHTML = `
        <details class="user-menu">
            <summary class="user-menu-trigger user-chip" aria-haspopup="menu" aria-expanded="false">
                <img class="user-chip-avatar" src="${escapeHtml(avatarUrl(user.avatarPath))}" alt="${escapeHtml(user.displayName)}">
                <span class="user-menu-name">${escapeHtml(user.displayName)}</span>
                <span class="user-menu-arrow" aria-hidden="true">&#9662;</span>
            </summary>
            <div class="user-menu-panel" role="menu">
                <div class="user-menu-meta">
                    <strong>${escapeHtml(user.displayName)}</strong>
                    <span>${escapeHtml(roleLabel(user.role))}</span>
                </div>
                <nav class="mobile-user-nav" aria-label="Разделы сайта">
                    ${links
                        .map(
                            (item) =>
                                `<a class="user-menu-link" href="${item.href}">${item.label}</a>`
                        )
                        .join('')}
                </nav>
                <a class="user-menu-link" href="/profile.html">Профиль</a>
                <button type="button" class="user-menu-link" id="logout-btn">Выйти</button>
            </div>
        </details>
    `;

    if (!user.verified) {
        const profileLink = actions.querySelector('a[href="/profile.html"]');
        if (profileLink) {
            profileLink.remove();
        }
    }

    document.getElementById('logout-btn').addEventListener('click', () => {
        logout().catch((error) => window.alert(error.message));
    });

    attachUserMenuBehavior(actions.querySelector('.user-menu'));
    renderSiteFooter(user);
    bindBrandLinks(document.querySelector('.topbar'));
    bindPageTransitions(nav);
    bindPageTransitions(actions);
    applyRevealAnimations(actions);
}

function normalizeTrackCommentsMap(rawComments) {
    const map = new Map();

    Object.entries(rawComments || {}).forEach(([trackId, comments]) => {
        map.set(
            Number(trackId),
            Array.isArray(comments)
                ? comments
                      .map((comment) => ({
                          id: Number(comment.id) || 0,
                          track_id: Number(comment.track_id) || Number(trackId) || 0,
                          timestamp_seconds: Math.max(0, Number(comment.timestamp_seconds) || 0),
                          body: String(comment.body || '').trim(),
                          created_at: comment.created_at || '',
                          streamer_name: String(comment.streamer_name || '').trim()
                      }))
                      .sort((left, right) => left.timestamp_seconds - right.timestamp_seconds)
                : []
        );
    });

    return map;
}

async function loadTrackCommentsMap(trackIds = []) {
    const uniqueTrackIds = [...new Set(trackIds.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0))];
    if (!uniqueTrackIds.length) {
        return new Map();
    }

    const payload = await apiFetch(`/api/track-comments?trackIds=${uniqueTrackIds.join(',')}`);
    return normalizeTrackCommentsMap(payload.comments);
}

function buildTrackCommentItems(comments = []) {
    if (!comments.length) {
        return `
            <div class="audio-comment-empty">
                Комментариев по таймкодам пока нет.
            </div>
        `;
    }

    return comments
        .map((comment) => {
            const label = `${formatTimestamp(comment.timestamp_seconds)} — ${comment.body}`.trim();
            return `
                <button type="button" class="audio-comment-item" data-comment-jump data-seconds="${comment.timestamp_seconds}" aria-label="${escapeHtml(label)}">
                    <time>${formatTimestamp(comment.timestamp_seconds)}</time>
                    <span>${escapeHtml(comment.body)}</span>
                </button>
            `;
        })
        .join('');
}

function buildTrackCommentMarkers(comments = []) {
    if (!comments.length) {
        return '<span class="audio-comment-empty-line">Пока без отметок</span>';
    }

    return comments
        .map((comment) => {
            const title = `${formatTimestamp(comment.timestamp_seconds)} — ${comment.body}`.trim();
            return `
                <button
                    type="button"
                    class="audio-comment-marker"
                    data-comment-marker
                    data-seconds="${comment.timestamp_seconds}"
                    title="${escapeHtml(title)}"
                    aria-label="${escapeHtml(title)}"
                ></button>
            `;
        })
        .join('');
}

function trackCommentBoardMarkup(trackId, comments = [], options = {}) {
    const editable = Boolean(options.editable);
    const boardId = Number(trackId) || 0;

    return `
        <section
            class="audio-comment-board"
            data-track-comment-board
            data-track-id="${boardId}"
            data-audio-id="audio-track-${boardId}"
            ${editable ? 'data-editable="true"' : ''}
        >
            <div class="audio-comment-board-head">
                <strong>Комментарии по таймкодам</strong>
                <span class="audio-comment-meta">${comments.length ? `${comments.length} отметок` : 'Пока пусто'}</span>
            </div>
            <div class="audio-comment-timeline" data-comment-timeline>
                ${buildTrackCommentMarkers(comments)}
            </div>
            ${
                editable
                    ? `
                        <div class="audio-comment-capture">
                            <button type="button" class="secondary" data-comment-capture>Взять текущий момент</button>
                            <span class="audio-comment-time" data-comment-time-label>Точка не выбрана</span>
                            <input type="hidden" value="" data-comment-time>
                        </div>
                        <div class="field audio-comment-field">
                            <label for="timeline-comment-${boardId}">Комментарий к моменту</label>
                            <textarea
                                id="timeline-comment-${boardId}"
                                data-comment-body
                                placeholder="Что важно услышать именно в этом месте"
                            ></textarea>
                        </div>
                        <button type="button" class="secondary audio-comment-submit" data-comment-submit>Добавить отметку</button>
                    `
                    : ''
            }
            <div class="audio-comment-list" data-comment-list>
                ${buildTrackCommentItems(comments)}
            </div>
        </section>
    `;
}

function getBoardAudio(board) {
    if (!board) {
        return null;
    }

    const audioId = board.dataset.audioId;
    return audioId ? document.getElementById(audioId) : null;
}

function positionTrackCommentMarkers(board) {
    const audio = getBoardAudio(board);
    const markers = Array.from(board.querySelectorAll('[data-comment-marker]'));
    if (!markers.length) {
        return;
    }

    const duration = audio && Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : null;
    const fallbackDuration =
        duration ||
        Math.max(
            ...markers.map((marker) => {
                const seconds = Number(marker.dataset.seconds);
                return Number.isFinite(seconds) ? seconds : 0;
            }),
            1
        );

    markers.forEach((marker) => {
        const seconds = Math.max(0, Number(marker.dataset.seconds) || 0);
        const left = Math.min(100, (seconds / fallbackDuration) * 100);
        marker.style.left = `${left}%`;
    });
}

function jumpAudioTo(board, seconds) {
    const audio = getBoardAudio(board);
    const targetTime = Math.max(0, Number(seconds) || 0);

    if (!audio) {
        return;
    }

    if (Number.isFinite(audio.duration) && audio.duration > 0) {
        audio.currentTime = Math.min(audio.duration, targetTime);
    } else {
        audio.currentTime = targetTime;
    }

    audio.play().catch(() => {
        // Автовоспроизведение может быть заблокировано браузером — это нормально.
    });
}

function bindTrackCommentBoards(root = document, options = {}) {
    if (!root) {
        return;
    }

    const boards = root.matches && root.matches('[data-track-comment-board]')
        ? [root]
        : Array.from(root.querySelectorAll ? root.querySelectorAll('[data-track-comment-board]') : []);

    boards.forEach((board) => {
        if (board.dataset.commentBoardReady === '1') {
            return;
        }

        board.dataset.commentBoardReady = '1';

        const audio = getBoardAudio(board);
        const captureButton = board.querySelector('[data-comment-capture]');
        const submitButton = board.querySelector('[data-comment-submit]');
        const timeInput = board.querySelector('[data-comment-time]');
        const timeLabel = board.querySelector('[data-comment-time-label]');
        const bodyField = board.querySelector('[data-comment-body]');

        board.querySelectorAll('[data-comment-marker], [data-comment-jump]').forEach((element) => {
            element.addEventListener('click', () => {
                jumpAudioTo(board, element.dataset.seconds);
            });
        });

        if (audio) {
            const refreshMarkers = () => positionTrackCommentMarkers(board);
            if (audio.readyState >= 1) {
                refreshMarkers();
            }

            audio.addEventListener('loadedmetadata', refreshMarkers);
            audio.addEventListener('durationchange', refreshMarkers);
        } else {
            positionTrackCommentMarkers(board);
        }

        if (captureButton && timeInput && timeLabel) {
            captureButton.addEventListener('click', () => {
                const seconds = audio ? Math.round(audio.currentTime || 0) : 0;
                timeInput.value = String(seconds);
                timeLabel.textContent = `Выбран момент ${formatTimestamp(seconds)}`;
            });
        }

        if (submitButton && timeInput && timeLabel && bodyField && typeof options.onSubmit === 'function') {
            submitButton.addEventListener('click', async () => {
                const rawTime = timeInput.value !== '' ? Number(timeInput.value) : Math.round((audio && audio.currentTime) || 0);
                const timestampSeconds = Math.max(0, Number.isFinite(rawTime) ? rawTime : 0);
                const body = bodyField.value.trim();

                if (!body) {
                    bodyField.focus();
                    window.alert('Напиши комментарий к выбранному моменту.');
                    return;
                }

                submitButton.disabled = true;
                try {
                    await options.onSubmit({
                        trackId: Number(board.dataset.trackId),
                        timestampSeconds,
                        body
                    });

                    bodyField.value = '';
                    timeInput.value = '';
                    timeLabel.textContent = 'Точка не выбрана';
                } finally {
                    submitButton.disabled = false;
                }
            });
        }
    });
}

async function guardPage(config) {
    const user = await getSession();

    if (!user) {
        startPageTransition('/login.html');
        return null;
    }

    if (config.roles && !config.roles.includes(user.role)) {
        startPageTransition(userHomePath(user));
        return null;
    }

    if (config.requireVerified && !user.verified) {
        startPageTransition('/index.html?verificationRequired=1');
        return null;
    }

    setupTopbar(config.activePath, user);
    document.body.classList.add('page-ready');
    applyRevealAnimations();

    if (config.bannerElement && !user.verified) {
        showMessage(
            config.bannerElement,
            'info',
            'Подтверди почту.',
            '<button class="button ghost" id="resend-mail-btn" type="button">Отправить письмо ещё раз</button>'
        );

        const resendButton = document.getElementById('resend-mail-btn');
        if (resendButton) {
            resendButton.addEventListener('click', async () => {
                try {
                    const payload = await apiFetch('/api/resend-verification', { method: 'POST' });
                    const extra = payload.previewUrl
                        ? `<a href="${payload.previewUrl}" target="_blank" rel="noreferrer">Открыть ссылку подтверждения</a>`
                        : '';
                    showMessage(config.bannerElement, 'info', payload.message, extra);
                } catch (error) {
                    showMessage(config.bannerElement, 'error', error.message);
                }
            });
        }
    }

    return user;
}

document.addEventListener('DOMContentLoaded', () => {
    ensureFavicon();
    renderSiteFooter(null);
    bindBrandLinks();
    bindPageTransitions();
    applyRevealAnimations();
});
