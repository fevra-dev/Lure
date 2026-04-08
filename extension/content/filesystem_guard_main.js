/**
 * extension/content/filesystem_guard_main.js
 *
 * FileSystemGuard — MAIN World API Interceptor
 *
 * Runs in the MAIN world at document_start to wrap the File System Access
 * API surface before page scripts can cache references:
 *   - window.showDirectoryPicker
 *   - window.showOpenFilePicker
 *   - window.showSaveFilePicker
 *   - FileSystemDirectoryHandle.prototype.entries / .values
 *   - FileSystemFileHandle.prototype.getFile / .createWritable
 *
 * MAIN world scripts cannot access chrome.* APIs. All observations are
 * forwarded via window.postMessage() to the isolated-world bridge script
 * (filesystem_guard_bridge.js) which relays to the service worker.
 *
 * Message source identifier: 'PHISHOPS_FSG'
 *
 * @module FileSystemGuardMain
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

(function () {
  const hasFSA = (
    typeof window.showDirectoryPicker !== 'undefined' ||
    typeof window.showOpenFilePicker !== 'undefined' ||
    typeof window.showSaveFilePicker !== 'undefined'
  );
  if (!hasFSA) return;

  const SOURCE = 'PHISHOPS_FSG';
  const sk = globalThis.__PHISHOPS_STEALTH;

  /* ------------------------------------------------------------------ */
  /*  Emit helper                                                        */
  /* ------------------------------------------------------------------ */

  function emit(type, data) {
    try {
      window.postMessage({ source: SOURCE, type, data }, '*');
    } catch { /* non-critical */ }
  }

  /* ------------------------------------------------------------------ */
  /*  1. window.showDirectoryPicker                                      */
  /* ------------------------------------------------------------------ */

  if (typeof window.showDirectoryPicker === 'function') {
    const origDirPicker = window.showDirectoryPicker;

    function wrappedDirPicker(options) {
      emit('FSG_DIRECTORY_PICKER_INVOKED', {
        mode: options?.mode || 'read',
        startIn: options?.startIn || null,
        timestamp: Date.now(),
      });
      if (sk) return sk.apply(origDirPicker, this, [options]);
      return origDirPicker.call(this, options);
    }

    if (sk) sk.patchToString(wrappedDirPicker, origDirPicker);
    window.showDirectoryPicker = wrappedDirPicker;
  }

  /* ------------------------------------------------------------------ */
  /*  2. window.showOpenFilePicker                                       */
  /* ------------------------------------------------------------------ */

  if (typeof window.showOpenFilePicker === 'function') {
    const origOpenPicker = window.showOpenFilePicker;

    function wrappedOpenPicker(options) {
      emit('FSG_FILE_PICKER_INVOKED', {
        multiple: !!options?.multiple,
        startIn: options?.startIn || null,
        timestamp: Date.now(),
      });
      if (sk) return sk.apply(origOpenPicker, this, [options]);
      return origOpenPicker.call(this, options);
    }

    if (sk) sk.patchToString(wrappedOpenPicker, origOpenPicker);
    window.showOpenFilePicker = wrappedOpenPicker;
  }

  /* ------------------------------------------------------------------ */
  /*  3. window.showSaveFilePicker                                       */
  /* ------------------------------------------------------------------ */

  if (typeof window.showSaveFilePicker === 'function') {
    const origSavePicker = window.showSaveFilePicker;

    function wrappedSavePicker(options) {
      emit('FSG_SAVE_PICKER_INVOKED', {
        startIn: options?.startIn || null,
        timestamp: Date.now(),
      });
      if (sk) return sk.apply(origSavePicker, this, [options]);
      return origSavePicker.call(this, options);
    }

    if (sk) sk.patchToString(wrappedSavePicker, origSavePicker);
    window.showSaveFilePicker = wrappedSavePicker;
  }

  /* ------------------------------------------------------------------ */
  /*  4. FileSystemDirectoryHandle.prototype.entries / .values          */
  /* ------------------------------------------------------------------ */

  if (typeof FileSystemDirectoryHandle !== 'undefined') {
    const proto = FileSystemDirectoryHandle.prototype;

    for (const method of ['entries', 'values', 'keys']) {
      if (typeof proto[method] === 'function') {
        if (sk) {
          sk.stealthWrapProto(proto, method, (target, thisArg, args) => {
            emit('FSG_DIRECTORY_ENUMERATION', {
              method,
              name: thisArg?.name || '',
              timestamp: Date.now(),
            });
            return sk.apply(target, thisArg, args);
          });
        } else {
          const origMethod = proto[method];
          proto[method] = function (...args) {
            emit('FSG_DIRECTORY_ENUMERATION', {
              method,
              name: this?.name || '',
              timestamp: Date.now(),
            });
            return origMethod.apply(this, args);
          };
        }
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /*  5. FileSystemFileHandle.prototype.getFile / .createWritable       */
  /* ------------------------------------------------------------------ */

  if (typeof FileSystemFileHandle !== 'undefined') {
    const proto = FileSystemFileHandle.prototype;

    if (typeof proto.getFile === 'function') {
      if (sk) {
        sk.stealthWrapProto(proto, 'getFile', (target, thisArg, args) => {
          emit('FSG_FILE_READ_ATTEMPT', {
            name: thisArg?.name || '',
            timestamp: Date.now(),
          });
          return sk.apply(target, thisArg, args);
        });
      } else {
        const origGetFile = proto.getFile;
        proto.getFile = function (...args) {
          emit('FSG_FILE_READ_ATTEMPT', {
            name: this?.name || '',
            timestamp: Date.now(),
          });
          return origGetFile.apply(this, args);
        };
      }
    }

    if (typeof proto.createWritable === 'function') {
      if (sk) {
        sk.stealthWrapProto(proto, 'createWritable', (target, thisArg, args) => {
          emit('FSG_WRITE_STREAM_OPENED', {
            name: thisArg?.name || '',
            timestamp: Date.now(),
          });
          return sk.apply(target, thisArg, args);
        });
      } else {
        const origCreateWritable = proto.createWritable;
        proto.createWritable = function (...args) {
          emit('FSG_WRITE_STREAM_OPENED', {
            name: this?.name || '',
            timestamp: Date.now(),
          });
          return origCreateWritable.apply(this, args);
        };
      }
    }
  }
})();

})();
