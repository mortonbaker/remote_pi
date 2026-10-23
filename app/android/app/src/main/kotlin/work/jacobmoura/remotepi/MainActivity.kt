package work.jacobmoura.remotepi

import android.content.Context
import android.content.RestrictionsManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Exposes the app's managed configuration (Android app restrictions, set by
 * the device owner — Guardian on the family tablets) to Dart. A managed
 * device ships its pairing this way, so the app is connected on first launch
 * with nothing to scan. Every value is a string; an unmanaged device gets {}.
 */
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "remotepi/managed_config")
            .setMethodCallHandler { call, result ->
                if (call.method != "get") return@setMethodCallHandler result.notImplemented()
                val rm = getSystemService(Context.RESTRICTIONS_SERVICE) as? RestrictionsManager
                val bundle = rm?.applicationRestrictions
                val out = HashMap<String, String>()
                bundle?.keySet()?.forEach { k -> bundle.getString(k)?.let { out[k] = it } }
                result.success(out)
            }
    }
}
