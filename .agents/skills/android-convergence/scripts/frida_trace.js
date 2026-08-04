'use strict';

function emit(kind, fields) {
  const record = Object.assign({kind: kind, ts: Date.now()}, fields || {});
  send(record);
}

function clipped(value) {
  try {
    const text = String(value);
    return text.length > 1024 ? text.slice(0, 1024) + '…' : text;
  } catch (_) {
    return '<unprintable>';
  }
}

function hookAll(className, methodName, eventName, serializer) {
  try {
    const cls = Java.use(className);
    const method = cls[methodName];
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        let fields = {};
        try {
          fields = serializer ? serializer(args) : {args: args.map(clipped)};
        } catch (error) {
          fields = {serialization_error: clipped(error)};
        }
        fields.class_name = className;
        fields.method = methodName;
        emit(eventName, fields);
        return overload.apply(this, args);
      };
    });
  } catch (error) {
    emit('hook-unavailable', {class_name: className, method: methodName, error: clipped(error)});
  }
}

Java.perform(function () {
  const intentFields = function (args) {
    const intent = args[0];
    return {intent: intent ? clipped(intent.toUri(0)) : null};
  };
  hookAll('android.app.Activity', 'startActivity', 'component-launch', intentFields);
  hookAll('android.content.ContextWrapper', 'startActivity', 'component-launch', intentFields);
  hookAll('android.content.ContextWrapper', 'startService', 'service-launch', intentFields);
  hookAll('android.content.ContextWrapper', 'startForegroundService', 'service-launch', intentFields);
  hookAll('android.content.ContextWrapper', 'sendBroadcast', 'broadcast-send', intentFields);

  hookAll('android.webkit.WebView', 'loadUrl', 'webview-load', function (args) {
    return {url: clipped(args[0]), extra_arg_count: Math.max(0, args.length - 1)};
  });
  hookAll('android.webkit.WebView', 'loadDataWithBaseURL', 'webview-load-data', function (args) {
    return {base_url: clipped(args[0]), mime_type: clipped(args[2]), encoding: clipped(args[3])};
  });
  hookAll('android.webkit.WebView', 'evaluateJavascript', 'webview-javascript', function (args) {
    return {script: clipped(args[0])};
  });
  hookAll('android.webkit.WebView', 'addJavascriptInterface', 'webview-bridge', function (args) {
    return {bridge_class: args[0] ? clipped(args[0].getClass().getName()) : null, name: clipped(args[1])};
  });

  hookAll('java.lang.System', 'load', 'native-load', function (args) {
    return {path: clipped(args[0])};
  });
  hookAll('java.lang.System', 'loadLibrary', 'native-load', function (args) {
    return {library: clipped(args[0])};
  });
  hookAll('dalvik.system.DexClassLoader', '$init', 'dex-load', function (args) {
    return {dex_path: clipped(args[0]), optimized_directory: clipped(args[1])};
  });
  hookAll('dalvik.system.PathClassLoader', '$init', 'dex-load', function (args) {
    return {path: clipped(args[0])};
  });
});

['android_dlopen_ext', 'dlopen'].forEach(function (name) {
  try {
    const address = Module.findGlobalExportByName
      ? Module.findGlobalExportByName(name)
      : Module.findExportByName(null, name);
    if (!address) {
      emit('hook-unavailable', {native_symbol: name});
      return;
    }
    Interceptor.attach(address, {
      onEnter: function (args) {
        let path = null;
        try {
          path = args[0].isNull() ? null : clipped(args[0].readUtf8String());
        } catch (_) {}
        emit('native-dlopen', {symbol: name, path: path});
      }
    });
  } catch (error) {
    emit('hook-unavailable', {native_symbol: name, error: clipped(error)});
  }
});
