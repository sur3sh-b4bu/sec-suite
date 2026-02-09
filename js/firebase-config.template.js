// Firebase Configuration Template
// IMPORTANT: Replace these values with your actual Firebase project credentials
// Get these from: Firebase Console > Project Settings > General > Your apps > Web app

const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_PROJECT_ID.appspot.com",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID",
    measurementId: "YOUR_MEASUREMENT_ID" // Optional
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Initialize Firebase services
const auth = firebase.auth();
const db = firebase.firestore();
const storage = firebase.storage();
const functions = firebase.functions();

// For local development with emulators (uncomment if using)
// if (location.hostname === 'localhost') {
//     auth.useEmulator('http://localhost:9099');
//     db.useEmulator('localhost', 8080);
//     storage.useEmulator('localhost', 9199);
//     functions.useEmulator('localhost', 5001);
// }

console.log('Firebase initialized successfully');
