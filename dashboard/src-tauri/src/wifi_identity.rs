//! SSID retrieval under the dashboard's macOS location permission.
#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{c_char, c_void, CStr};
    type Id = *mut c_void;
    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Id;
        fn objc_msgSend();
        fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra: usize) -> Id;
        fn objc_registerClassPair(class: Id);
        fn class_addMethod(class: Id, selector: Id, implementation: unsafe extern "C" fn(Id, Id, Id), types: *const c_char) -> bool;
    }
    #[link(name = "CoreWLAN", kind = "framework")]
    extern "C" {}
    #[link(name = "CoreLocation", kind = "framework")]
    extern "C" {}
    unsafe fn send(receiver: Id, selector: &'static [u8]) -> Id {
        let f: unsafe extern "C" fn(Id, Id) -> Id = std::mem::transmute(objc_msgSend as *const ());
        f(receiver, sel_registerName(selector.as_ptr().cast()))
    }
    pub fn ssid() -> Option<String> {
        unsafe {
            let pool = send(
                objc_getClass(b"NSAutoreleasePool\0".as_ptr().cast()),
                b"new\0",
            );
            let client = send(
                objc_getClass(b"CWWiFiClient\0".as_ptr().cast()),
                b"sharedWiFiClient\0",
            );
            let interface = send(client, b"interface\0");
            let name = send(interface, b"ssid\0");
            let bytes = send(name, b"UTF8String\0") as *const c_char;
            let value = if bytes.is_null() {
                None
            } else {
                Some(CStr::from_ptr(bytes).to_string_lossy().into_owned())
            };
            send(pool, b"drain\0");
            value.filter(|s| !s.is_empty() && s != "<redacted>")
        }
    }
    unsafe extern "C" fn authorization_changed(_: Id, _: Id, _: Id) {}
    pub fn request_permission() {
        // The request is scheduled on the main thread by the Tauri command.
        // Keep both manager and delegate alive for the asynchronous sheet.
        static MANAGER: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        unsafe {
            let manager = *MANAGER.get_or_init(|| {
                let mut class = objc_getClass(b"ProxyRouterLocationDelegate\0".as_ptr().cast());
                if class.is_null() {
                    class = objc_allocateClassPair(objc_getClass(b"NSObject\0".as_ptr().cast()), b"ProxyRouterLocationDelegate\0".as_ptr().cast(), 0);
                    class_addMethod(class, sel_registerName(b"locationManagerDidChangeAuthorization:\0".as_ptr().cast()), authorization_changed, b"v@:@\0".as_ptr().cast());
                    objc_registerClassPair(class);
                }
                let delegate = send(class, b"new\0");
                let manager = send(objc_getClass(b"CLLocationManager\0".as_ptr().cast()), b"new\0");
                let set: unsafe extern "C" fn(Id, Id, Id) = std::mem::transmute(objc_msgSend as *const ());
                set(manager, sel_registerName(b"setDelegate:\0".as_ptr().cast()), delegate);
                manager as usize
            }) as Id;
            send(manager, b"requestWhenInUseAuthorization\0");
        }
    }

}
pub fn ssid() -> Option<String> {
    #[cfg(target_os = "macos")]
    return mac::ssid();
    #[cfg(not(target_os = "macos"))]
    None
}
pub fn request_permission() {
    #[cfg(target_os = "macos")]
    mac::request_permission();
}
