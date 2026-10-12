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
    pub fn request_permission() {
        // Main-thread, process-lifetime manager: the authorization sheet is asynchronous.
        static MANAGER: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        unsafe {
            let manager = *MANAGER.get_or_init(|| {
                send(
                    objc_getClass(b"CLLocationManager\0".as_ptr().cast()),
                    b"new\0",
                ) as usize
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
