// server.js - Node.js Express Server for Google Sign-In Verification
const express = require('express');
const path = require('path'); // <-- Added explicit path require for robustness
const { OAuth2Client } = require('google-auth-library');

// --- Configuration via Environment Variables ---
const CLIENT_ID = process.env.CLIENT_ID;
const TARGET_URL = process.env.TARGET_URL || 'https://sites.google.com/kaneland.org/kanelandapplicationlauncher';
const PORT = process.env.PORT || 3000;

if (!CLIENT_ID) {
    // Crucial check: if CLIENT_ID is missing, the server cannot verify tokens and must crash.
    console.error("FATAL ERROR: CLIENT_ID environment variable is not set.");
    console.error("Please configure the CLIENT_ID in your Railway project variables.");
    process.exit(1); 
}

const app = express();
const client = new OAuth2Client(CLIENT_ID);

// Middleware to parse JSON bodies from client requests
app.use(express.json());

// Serve the static HTML file for the login page
app.get('/', (req, res) => {
    // Use the absolute path to ensure the file is always found regardless of the execution context
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- SECURE ACCESS CONTROL LOGIC ---
const RESTRICTED_EMAILS = new Set([
    "blockeduser1@kaneland.org",
    "blockeduser2@kaneland.org",
    "user_to_deny@kaneland.org",
    // Add all specific emails you want to restrict here. 
]);

/**
 * Endpoint to verify the Google ID Token and check access.
 */
app.post('/verify-token', async (req, res) => {
    const { idToken } = req.body;

    if (!idToken) {
        return res.status(400).json({ success: false, message: 'ID Token is missing.' });
    }

    let payload;
    try {
        // 1. Verify the token's authenticity using Google's library
        const ticket = await client.verifyIdToken({
            idToken: idToken,
            audience: CLIENT_ID, 
        });
        payload = ticket.getPayload();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return res.status(401).json({ success: false, message: 'Invalid or expired sign-in credential.' });
    }

    // 2. Extract the email from the verified payload
    const email = payload['email'].toLowerCase();
    
    // Check if the user is from the required domain for extra safety
    if (!email.endsWith('@kaneland.org')) {
        return res.status(403).json({ success: false, message: 'Access denied: Must sign in with a @kaneland.org account.' });
    }

    // 3. Check against the restricted list
    if (RESTRICTED_EMAILS.has(email)) {
        console.log(`Access DENIED for restricted user: ${email}`);
        return res.status(403).json({ success: false, message: `Access denied for ${email}. You are not authorized to view this site.` });
    }

    // 4. Access Granted! Redirect the user to the target site.
    console.log(`Access GRANTED for authorized user: ${email}`);
    return res.status(200).json({ success: true, redirectUrl: TARGET_URL });
});

// Start the server
app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`✅ Server is running on port ${PORT}`);
    console.log(`🔗 Target URL: ${TARGET_URL}`);
    console.log(`🌐 Serving login gate on internal port ${PORT}`);
    console.log(`======================================================\n`);
});
