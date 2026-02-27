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
                <data android:mimeType="*/*" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.SEND_MULTIPLE" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="image/*" />
                <data android:mimeType="*/*" />
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
    @com.getcapacitor.annotation.CapacitorPlugin(name = "NativeShareProxy")
    public static class NativeShareProxy extends com.getcapacitor.Plugin {
        public static final java.util.ArrayList<String> pendingIntents = new java.util.ArrayList<>();
        public static final java.util.ArrayList<String> pendingIntentTexts = new java.util.ArrayList<>();

        @com.getcapacitor.PluginMethod
        public void getPendingIntents(com.getcapacitor.PluginCall call) {
            com.getcapacitor.JSObject ret = new com.getcapacitor.JSObject();
            if (!pendingIntents.isEmpty()) {
                ret.put("url", pendingIntents.remove(0));
            } else if (!pendingIntentTexts.isEmpty()) {
                ret.put("text", pendingIntentTexts.remove(0));
            }
            call.resolve(ret);
        }
    }

    @Override
    public void onCreate(android.os.Bundle savedInstanceState) {
        registerPlugin(NativeShareProxy.class);
        super.onCreate(savedInstanceState);
    }

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
        if (intent == null) return;
        
        String action = intent.getAction();
        if (!android.content.Intent.ACTION_SEND.equals(action) && !android.content.Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            return;
        }
        
        // Handle URL or Text sharing (like from Edge Browser)
        String sharedText = intent.getStringExtra(android.content.Intent.EXTRA_TEXT);
        if (sharedText != null && !sharedText.isEmpty()) {
            final String safeText = sharedText.replace("'", "\\'").replace("\\n", "\\\\n");
            NativeShareProxy.pendingIntentTexts.add(safeText);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (bridge != null && bridge.getWebView() != null) {
                        bridge.getWebView().evaluateJavascript("window.dispatchEvent(new CustomEvent('nativeShareIntentPing'));", null);
                    }
                }
            });
            setIntent(new android.content.Intent());
            return;
        }

        // Handle File Binary sharing (like from Gallery or File Manager)
        java.util.ArrayList<android.net.Uri> uris = new java.util.ArrayList<>();
        if (android.content.Intent.ACTION_SEND.equals(action)) {
            android.net.Uri uri = intent.getParcelableExtra(android.content.Intent.EXTRA_STREAM);
            if (uri != null) uris.add(uri);
        } else if (android.content.Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            java.util.ArrayList<android.net.Uri> list = intent.getParcelableArrayListExtra(android.content.Intent.EXTRA_STREAM);
            if (list != null) uris.addAll(list);
        }

        // Offload extraction to a background thread to prevent Main UI Thread ANR timeouts for large files
        java.util.concurrent.Executors.newSingleThreadExecutor().execute(new Runnable() {
            @Override
            public void run() {
                for (android.net.Uri uri : uris) {
                    if ("content".equals(uri.getScheme()) || "file".equals(uri.getScheme())) {
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
                            
                            if ("content".equals(uri.getScheme())) {
                                try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null, null)) {
                                    if (cursor != null && cursor.moveToFirst()) {
                                        int nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                                        if (nameIndex >= 0) {
                                            String name = cursor.getString(nameIndex);
                                            if (name != null && name.contains(".")) displayName = name;
                                        }
                                    }
                                } catch (Exception ex) { }
                            } else if ("file".equals(uri.getScheme())) {
                                displayName = new java.io.File(uri.getPath()).getName();
                            }

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
                                
                                NativeShareProxy.pendingIntents.add(safeUri);
                                
                                // Fire structural Ping to WebView securely
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (bridge != null && bridge.getWebView() != null) {
                                            bridge.getWebView().evaluateJavascript("window.dispatchEvent(new CustomEvent('nativeShareIntentPing'));", null);
                                        }
                                    }
                                });
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        });
        
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
            console.log('Successfully injected Native Cache Scoped Storage Bypass and NativeShareProxy Plugin into MainActivity.java');
        }
    } else {
        console.log('MainActivity.java already contains handleShareIntent.');
    }
}

