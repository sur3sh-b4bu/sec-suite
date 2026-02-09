// Firebase Configuration
// Used only for storing scan results in PDF format

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getStorage, ref, uploadBytes, getDownloadURL } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-storage.js";
import { getFirestore, collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js";

// Your Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyBHdwCxlEHEfzNLQrTjCJKmqMOxcLzRxNY",
    authDomain: "web-sca.firebaseapp.com",
    projectId: "web-sca",
    storageBucket: "web-sca.firebasestorage.app",
    messagingSenderId: "961814572261",
    appId: "1:961814572261:web:87563bbd05397f32d9f80c",
    measurementId: "G-TQFCF0XRQH"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const storage = getStorage(app);
const db = getFirestore(app);

// Export Firebase services
export { app, storage, db, ref, uploadBytes, getDownloadURL, collection, addDoc, serverTimestamp };

console.log('🔥 Firebase initialized for result storage');
