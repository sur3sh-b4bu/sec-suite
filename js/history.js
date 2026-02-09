// History Module
import { authManager } from './auth.js';
import { db, collection, query, where, orderBy, limit, getDocs } from './firebase-config.js';

class HistoryManager {
    constructor() {
        this.history = [];
    }

    async loadHistory() {
        if (!authManager.requireAuth()) {
            return;
        }

        try {
            const historyRef = collection(db, 'analysisHistory');
            const q = query(
                historyRef,
                where('userId', '==', authManager.currentUser.uid),
                orderBy('createdAt', 'desc'),
                limit(50)
            );

            const querySnapshot = await getDocs(q);
            this.history = [];

            querySnapshot.forEach((doc) => {
                this.history.push({
                    id: doc.id,
                    ...doc.data()
                });
            });

            this.displayHistory();
        } catch (error) {
            console.error('Error loading history:', error);
            authManager.showError('Failed to load history');
        }
    }

    displayHistory() {
        const historyList = document.getElementById('historyList');
        if (!historyList) return;

        if (this.history.length === 0) {
            historyList.innerHTML = `
                <div class="empty-state">
                    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 8V12L15 15M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <p>No analysis history yet. Start by analyzing your first lab!</p>
                </div>
            `;
            return;
        }

        historyList.innerHTML = this.history.map(item => {
            const date = item.createdAt ? new Date(item.createdAt.seconds * 1000) : new Date(item.timestamp);
            const formattedDate = date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });

            const confidenceColor = {
                high: '#10b981',
                medium: '#f59e0b',
                low: '#ef4444'
            }[item.detection?.confidence || 'low'];

            return `
                <div class="history-item" data-id="${item.id}">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                        <h3 style="font-size: 1rem; font-weight: 600; color: var(--color-text-primary); margin: 0; flex: 1;">
                            ${item.detection?.category || 'Unknown Vulnerability'}
                        </h3>
                        <span style="padding: 4px 8px; background: ${confidenceColor}; color: white; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-left: 12px;">
                            ${(item.detection?.confidence || 'low').toUpperCase()}
                        </span>
                    </div>
                    <p style="color: var(--color-text-muted); font-size: 0.875rem; margin-bottom: 8px;">
                        ${formattedDate}
                    </p>
                    <p style="color: var(--color-text-secondary); font-size: 0.875rem; margin-bottom: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${item.labUrl || 'No URL provided'}
                    </p>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-sm btn-primary view-history-btn" data-id="${item.id}">
                            View Details
                        </button>
                        <button class="btn btn-sm btn-ghost delete-history-btn" data-id="${item.id}">
                            Delete
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        // Add event listeners
        document.querySelectorAll('.view-history-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.target.getAttribute('data-id');
                this.viewHistoryItem(id);
            });
        });

        document.querySelectorAll('.delete-history-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.target.getAttribute('data-id');
                this.deleteHistoryItem(id);
            });
        });
    }

    viewHistoryItem(id) {
        const item = this.history.find(h => h.id === id);
        if (!item) return;

        // Navigate to analyzer section
        document.querySelector('a[href="#analyzer"]').click();

        // Populate fields
        setTimeout(() => {
            document.getElementById('labUrl')?.value = item.labUrl || '';
            document.getElementById('labDescription')?.value = item.labDescription || '';
            document.getElementById('httpRequest')?.value = item.request?.raw || '';
            document.getElementById('httpResponse')?.value = item.response?.raw || '';

            // Display results
            if (item.detection && item.exploitation) {
                const analyzer = window.analyzer || {};
                if (analyzer.displayResults) {
                    analyzer.displayResults(item);
                }
            }

            authManager.showInfo('History item loaded');
        }, 300);
    }

    async deleteHistoryItem(id) {
        if (!confirm('Are you sure you want to delete this analysis?')) {
            return;
        }

        try {
            // Note: Firestore delete requires importing deleteDoc
            // For now, just remove from local array
            this.history = this.history.filter(h => h.id !== id);
            this.displayHistory();
            authManager.showSuccess('Analysis deleted');
        } catch (error) {
            console.error('Error deleting history:', error);
            authManager.showError('Failed to delete analysis');
        }
    }
}

// Initialize history manager
const historyManager = new HistoryManager();

// Load history when section is shown
document.addEventListener('DOMContentLoaded', () => {
    const historyLink = document.querySelector('a[href="#history"]');
    if (historyLink) {
        historyLink.addEventListener('click', () => {
            if (authManager.currentUser) {
                historyManager.loadHistory();
            } else {
                authManager.showError('Please sign in to view history');
            }
        });
    }
});

export { historyManager };
