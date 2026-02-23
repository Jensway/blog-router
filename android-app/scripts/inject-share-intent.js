const fs = require('fs');
const path = require('path');

// Wait for capacitor to layout the android platform, then inject the Share Intents
const manifestPath = path.join(__dirname, '..', 'android', 'app', 'src', 'main', 'AndroidManifest.xml');

if (!fs.existsSync(manifestPath)) {
    console.error(`ERROR: AndroidManifest.xml not found at ${manifestPath}`);
    process.exit(1);
}

let manifest = fs.readFileSync(manifestPath, 'utf8');

// The <intent-filter> we need to inject into the <activity> block.
// This tells Android the OS that our app can handle SEND intents (sharing text/images to our app)
const shareIntentFilter = `
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
                <data android:mimeType="image/*" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.SEND_MULTIPLE" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="image/*" />
            </intent-filter>
`;

if (manifest.includes('android.intent.action.SEND')) {
    console.log('Manifest already has SEND intents configured.');
} else {
    // Inject right before the closing </activity> tag of MainActivity
    manifest = manifest.replace(/(<\/activity>)/, `${shareIntentFilter}$1`);
    fs.writeFileSync(manifestPath, manifest, 'utf8');
    console.log('Successfully injected Share Intent filter into AndroidManifest.xml');
}
