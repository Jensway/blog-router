import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// -------------------------------------------------------------
// Also Inject Native Java Scoped Storage Bypass into MainActivity
// -------------------------------------------------------------
const mainActivityPath = path.join(__dirname, '..', 'android', 'app', 'src', 'main', 'java', 'com', 'sharecenter', 'app', 'MainActivity.java');

if (fs.existsSync(mainActivityPath)) {
    let mainActivity = fs.readFileSync(mainActivityPath, 'utf8');

    const javaMethods = `
    @Override
    public void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        handleShareIntent(intent);
    }

    @Override
    public void onResume() {
        super.onResume();
        handleShareIntent(getIntent());
    }

    private void handleShareIntent(android.content.Intent intent) {
        if (intent == null || !android.content.Intent.ACTION_SEND.equals(intent.getAction())) {
            return;
        }
        
        android.net.Uri uri = intent.getParcelableExtra(android.content.Intent.EXTRA_STREAM);
        if (uri != null && "content".equals(uri.getScheme())) {
            try {
                // Determine Extension
                String ext = "bin";
                String mimeType = getContentResolver().getType(uri);
                if (mimeType != null) {
                    if (mimeType.contains("jpeg") || mimeType.contains("jpg")) ext = "jpg";
                    else if (mimeType.contains("png")) ext = "png";
                    else if (mimeType.contains("mp4")) ext = "mp4";
                    else if (mimeType.contains("pdf")) ext = "pdf";
                    else if (mimeType.contains("android.package-archive") || mimeType.contains("apk")) ext = "apk";
                    else if (mimeType.contains("zip")) ext = "zip";
                }
                
                String displayName = "shared_" + System.currentTimeMillis() + "." + ext;
                try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null, null)) {
                    if (cursor != null && cursor.moveToFirst()) {
                        int nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                        if (nameIndex >= 0) {
                            String name = cursor.getString(nameIndex);
                            if (name != null && name.contains(".")) displayName = name;
                        }
                    }
                } catch (Exception ex) { }

                // Bypass Android 13 Scoped Storage by natively caching the stream securely
                java.io.InputStream inputStream = getContentResolver().openInputStream(uri);
                if (inputStream != null) {
                    java.io.File tempFile = new java.io.File(getCacheDir(), displayName);
                    java.io.FileOutputStream outputStream = new java.io.FileOutputStream(tempFile);
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                    inputStream.close();
                    outputStream.close();
                    
                    final String safeUri = android.net.Uri.fromFile(tempFile).toString();
                    
                    // Fire Native JS Event into WebView securely!
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (bridge != null && bridge.getWebView() != null) {
                                String script = "window.dispatchEvent(new CustomEvent('nativeShareIntent', { detail: { url: '" + safeUri + "' } }));";
                                bridge.getWebView().evaluateJavascript(script, null);
                            }
                        }
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        // Consume intent so it doesn't fire again
        setIntent(new android.content.Intent());
    }
`;

    if (!mainActivity.includes('handleShareIntent')) {
        // Find the last curly brace closing the MainActivity class and inject our methods
        const lastBraceIndex = mainActivity.lastIndexOf('}');
        if (lastBraceIndex !== -1) {
            mainActivity = mainActivity.slice(0, lastBraceIndex) + javaMethods + '\n}\n';
            fs.writeFileSync(mainActivityPath, mainActivity, 'utf8');
            console.log('Successfully injected Native Cache Scoped Storage Bypass into MainActivity.java');
        }
    } else {
        console.log('MainActivity.java already contains handleShareIntent.');
    }
}

