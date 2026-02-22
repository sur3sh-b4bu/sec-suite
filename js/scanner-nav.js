/**
 * CYBER HUD V2 - NAVIGATION & DECORATION SYSTEM
 * Dynamically handles menu generation, premium icons, and HUD visuals.
 */

// SVG Icons (Lucide style)
const icons = {
    home: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
    zap: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    code: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
    lock: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
    server: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
    shield: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    globe: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    eye: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
    bug: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>`
};

const scanners = [
    {
        category: 'Injection',
        icon: icons.code,
        items: [
            { name: 'SQL Injection', url: 'sqli.html', icon: icons.code },
            { name: 'XSS Scanner', url: 'xss.html', icon: icons.code },
            { name: 'XXE Injection', url: 'xxe.html', icon: icons.code },
            { name: 'SSTI Detection', url: 'ssti.html', icon: icons.code },
            { name: 'NoSQL Injection', url: 'nosql.html', icon: icons.code },
            { name: 'OS Command', url: 'cmdi.html', icon: icons.code },
            { name: 'Host Header', url: 'host-header.html', icon: icons.server }
        ]
    },
    {
        category: 'Auth & Access',
        icon: icons.lock,
        items: [
            { name: 'Authentication', url: 'authentication.html', icon: icons.lock },
            { name: 'Access Control', url: 'access-control.html', icon: icons.shield },
            { name: 'OAuth Security', url: 'oauth.html', icon: icons.lock },
            { name: 'JWT Analysis', url: 'jwt.html', icon: icons.lock }
        ]
    },
    {
        category: 'Web Matrix',
        icon: icons.globe,
        items: [
            { name: 'CSRF Protection', url: 'csrf.html', icon: icons.globe },
            { name: 'Clickjacking', url: 'clickjacking.html', icon: icons.globe },
            { name: 'DOM Vulnerabilities', url: 'dom.html', icon: icons.code },
            { name: 'CORS Configuration', url: 'cors.html', icon: icons.server },
            { name: 'WebSocket Sec', url: 'websocket.html', icon: icons.server },
            { name: 'Proto Pollution', url: 'prototype-pollution.html', icon: icons.code }
        ]
    },
    {
        category: 'Architecture',
        icon: icons.server,
        items: [
            { name: 'SSRF Module', url: 'ssrf.html', icon: icons.server },
            { name: 'File Upload', url: 'file-upload.html', icon: icons.code },
            { name: 'Path Traversal', url: 'path-traversal.html', icon: icons.bug },
            { name: 'Business Logic', url: 'business-logic.html', icon: icons.zap },
            { name: 'Race Condition', url: 'race-condition.html', icon: icons.zap },
            { name: 'Deserialization', url: 'deserialization.html', icon: icons.bug },
            { name: 'API Testing', url: 'api-testing.html', icon: icons.server },
            { name: 'GraphQL Audit', url: 'graphql.html', icon: icons.code },
            { name: 'LLM Attacks', url: 'llm.html', icon: icons.zap }
        ]
    },
    {
        category: 'Infrastructure',
        icon: icons.zap,
        items: [
            { name: 'Cache Poisoning', url: 'cache-poisoning.html', icon: icons.zap },
            { name: 'Cache Deception', url: 'cache-deception.html', icon: icons.zap },
            { name: 'HTTP Smuggling', url: 'smuggling.html', icon: icons.server },
            { name: 'Info Disclosure', url: 'info-disclosure.html', icon: icons.eye },
            { name: 'Brute Force', url: 'brute-force.html', icon: icons.zap }
        ]
    },
    {
        category: 'Cloud Security',
        icon: icons.shield,
        items: [
            { name: 'Firebase & GCP', url: 'firebase-gcp.html', icon: icons.shield },
            { name: 'Firebase Auth', url: 'firebase-auth.html', icon: icons.lock },
            { name: 'Firebase Storage', url: 'firebase-storage.html', icon: icons.server },
            { name: 'Firebase Rules', url: 'firebase-rules.html', icon: icons.code },
            { name: 'GCP Functions', url: 'gcp-functions.html', icon: icons.zap },
            { name: 'GCP Storage', url: 'gcp-storage.html', icon: icons.server },
            { name: 'GCP Metadata', url: 'gcp-metadata.html', icon: icons.bug }
        ]
    }
];

class CyberHUDSystem {
    constructor() {
        this.currentPath = window.location.pathname.split('/').pop() || 'index.html';
        this.isInHtmlDir = window.location.pathname.includes('/html/');
        this.init();
    }

    getPathPrefix(forScanner) {
        return this.isInHtmlDir ? (forScanner ? '' : '../') : (forScanner ? 'html/' : '');
    }

    init() {
        this.injectHUDDecorations();
        this.setupNavigation();
        this.setupMobileMenu();
        this.animateNavOnScroll();
    }

    injectHUDDecorations() {
        if (!document.querySelector('.hud-decoration')) {
            const blobs = `
                <div class="hud-decoration hud-top-left"></div>
                <div class="hud-decoration hud-bottom-right"></div>
            `;
            const style = document.createElement('style');
            style.textContent = `
                .hud-decoration {
                    position: fixed;
                    width: 60vw;
                    height: 60vw;
                    border-radius: 50%;
                    filter: blur(150px);
                    z-index: -2;
                    opacity: 0.1;
                    pointer-events: none;
                }
                .hud-top-left { top: -200px; left: -200px; background: var(--clr-primary, #3b82f6); }
                .hud-bottom-right { bottom: -200px; right: -200px; background: var(--clr-secondary, #8b5cf6); }
                @media (max-width: 768px) { .hud-decoration { width: 100vw; height: 100vw; } }
            `;
            document.head.appendChild(style);
            document.body.insertAdjacentHTML('afterbegin', blobs);
        }
    }

    setupNavigation() {
        const navMenu = document.querySelector('.nav-menu');
        const navBrand = document.querySelector('.brand-text');
        if (navBrand) navBrand.textContent = 'CyberSec Suite';
        if (!navMenu) return;

        // Add Menu Toggle for mobile
        const container = document.querySelector('.nav-container');
        if (container && !document.querySelector('.menu-toggle')) {
            const toggle = document.createElement('button');
            toggle.className = 'menu-toggle';
            toggle.innerHTML = `<i data-lucide="menu"></i>`;
            container.appendChild(toggle);
        }

        navMenu.innerHTML = '';
        const scannerPrefix = this.getPathPrefix(true);
        const homePrefix = this.getPathPrefix(false);

        // Dashboard Link
        const homeLink = document.createElement('a');
        homeLink.href = `${homePrefix}index.html`;
        homeLink.className = `nav-link ${this.currentPath === 'index.html' ? 'active' : ''}`;
        homeLink.innerHTML = `<span style="display:flex;align-items:center;gap:8px;">${icons.home} Dashboard</span>`;
        navMenu.appendChild(homeLink);

        // mega menu trigger
        const trigger = document.createElement('div');
        trigger.className = 'dropdown-trigger';
        trigger.innerHTML = `
            <span class="nav-link ${this.currentPath !== 'index.html' ? 'active' : ''}" style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                ${icons.zap} Modules
                <svg class="dropdown-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <path d="M6 9l6 6 6-6"/>
                </svg>
            </span>
            <div class="mega-menu">
                <div class="mega-menu-grid">
                    ${scanners.map(cat => `
                        <div class="mega-menu-column">
                            <h3 class="mega-menu-title" style="display:flex;align-items:center;gap:8px;">
                                ${cat.icon} ${cat.category}
                            </h3>
                            <div class="mega-menu-items">
                                ${cat.items.map(item => `
                                    <a href="${scannerPrefix}${item.url}" class="mega-menu-item ${this.currentPath === item.url ? 'active' : ''}">
                                        <span class="item-icon">${item.icon}</span>
                                        <span class="item-name">${item.name}</span>
                                    </a>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        navMenu.appendChild(trigger);
    }

    setupMobileMenu() {
        const scannerPrefix = this.getPathPrefix(true);
        const homePrefix = this.getPathPrefix(false);

        const overlay = document.createElement('div');
        overlay.className = 'mobile-nav-overlay';
        document.body.appendChild(overlay);

        const sidebar = document.createElement('div');
        sidebar.className = 'mobile-nav';
        sidebar.innerHTML = `
            <div class="mobile-nav-header">
                <span class="brand-text">CyberSec Suite</span>
                <button class="menu-close" style="background:none;border:none;color:#fff;cursor:pointer;">
                    <i data-lucide="x"></i>
                </button>
            </div>
            <div class="mobile-menu-items">
                <a href="${homePrefix}index.html" class="mega-menu-item ${this.currentPath === 'index.html' ? 'active' : ''}">
                    <span class="item-icon">${icons.home}</span>
                    <span class="item-name">Dashboard</span>
                </a>
                ${scanners.map(cat => `
                    <div class="mobile-category-title">${cat.category}</div>
                    ${cat.items.map(item => `
                        <a href="${scannerPrefix}${item.url}" class="mega-menu-item ${this.currentPath === item.url ? 'active' : ''}">
                            <span class="item-icon">${item.icon}</span>
                            <span class="item-name">${item.name}</span>
                        </a>
                    `).join('')}
                `).join('')}
            </div>
        `;
        document.body.appendChild(sidebar);

        const toggleBtn = document.querySelector('.menu-toggle');
        const closeBtn = sidebar.querySelector('.menu-close');

        const toggleMenu = (open) => {
            sidebar.classList.toggle('open', open);
            overlay.classList.toggle('open', open);
            document.body.style.overflow = open ? 'hidden' : '';
        };

        if (toggleBtn) toggleBtn.onclick = () => toggleMenu(true);
        if (closeBtn) closeBtn.onclick = () => toggleMenu(false);
        overlay.onclick = () => toggleMenu(false);

        // Re-init icons for newly added elements
        if (window.lucide) window.lucide.createIcons();
    }

    animateNavOnScroll() {
        const nav = document.querySelector('.navbar');
        if (!nav) return;
        window.addEventListener('scroll', () => {
            if (window.scrollY > 20) {
                nav.style.top = '10px';
                nav.style.height = '64px';
                nav.style.background = 'rgba(2, 3, 8, 0.95)';
            } else {
                nav.style.top = '20px';
                nav.style.height = '74px';
                nav.style.background = 'var(--clr-surface)';
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new CyberHUDSystem();
});
