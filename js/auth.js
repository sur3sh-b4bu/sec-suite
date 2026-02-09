// Authentication Module - Modern Firebase v9+ SDK
import {
    auth,
    db,
    GoogleAuthProvider,
    signInWithPopup,
    signOut,
    onAuthStateChanged,
    doc,
    getDoc,
    setDoc,
    updateDoc,
    serverTimestamp
} from './firebase-config.js';

class AuthManager {
    constructor() {
        this.currentUser = null;
        this.initAuthListener();
    }

    initAuthListener() {
        onAuthStateChanged(auth, (user) => {
            this.currentUser = user;
            this.updateUI(user);

            if (user) {
                console.log('User signed in:', user.email);
                this.loadUserData(user.uid);
            } else {
                console.log('User signed out');
            }
        });
    }

    updateUI(user) {
        const loginBtn = document.getElementById('loginBtn');
        const userMenu = document.getElementById('userMenu');
        const userName = document.getElementById('userName');
        const userAvatar = document.getElementById('userAvatar');

        if (user) {
            loginBtn.style.display = 'none';
            userMenu.style.display = 'flex';
            userName.textContent = user.displayName || user.email;
            userAvatar.src = user.photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.email)}&background=6366f1&color=fff`;
        } else {
            loginBtn.style.display = 'block';
            userMenu.style.display = 'none';
        }
    }

    async signInWithGoogle() {
        try {
            const provider = new GoogleAuthProvider();
            const result = await signInWithPopup(auth, provider);

            // Create user profile in Firestore if new user
            const userRef = doc(db, 'users', result.user.uid);
            const userDoc = await getDoc(userRef);

            if (!userDoc.exists()) {
                await setDoc(userRef, {
                    email: result.user.email,
                    displayName: result.user.displayName,
                    photoURL: result.user.photoURL,
                    createdAt: serverTimestamp(),
                    lastLogin: serverTimestamp()
                });
            } else {
                await updateDoc(userRef, {
                    lastLogin: serverTimestamp()
                });
            }

            this.showSuccess('Signed in successfully!');
            return result.user;
        } catch (error) {
            console.error('Sign in error:', error);
            this.showError('Failed to sign in. Please try again.');
            throw error;
        }
    }

    async signOutUser() {
        try {
            await signOut(auth);
            this.showSuccess('Signed out successfully');
            console.log('User signed out successfully');
        } catch (error) {
            console.error('Sign out error:', error);
            this.showError('Failed to sign out. Please try again.');
        }
    }

    async loadUserData(userId) {
        try {
            const userRef = doc(db, 'users', userId);
            const userDoc = await getDoc(userRef);
            if (userDoc.exists()) {
                const userData = userDoc.data();
                console.log('User data loaded:', userData);
            }
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    }

    requireAuth() {
        if (!this.currentUser) {
            this.showError('Please sign in to use this feature');
            return false;
        }
        return true;
    }

    showNotification(message, type = 'info') {
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            info: '#3b82f6',
            warning: '#f59e0b'
        };

        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 90px;
            right: 20px;
            background: ${colors[type]};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
            z-index: 10000;
            animation: slideInRight 0.3s ease-out;
            font-weight: 500;
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showInfo(message) {
        this.showNotification(message, 'info');
    }
}

// Initialize auth manager
const authManager = new AuthManager();

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
            authManager.signInWithGoogle();
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            authManager.signOutUser();
        });
    }
});

// Add animations to CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Export for use in other modules
export { authManager };
