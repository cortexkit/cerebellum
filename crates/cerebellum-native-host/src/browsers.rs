//! Home-relative native-host manifest directories for future installers.
//! Only Chrome is enabled because the shipped parent check admits Chrome alone.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserManifestLocation {
    pub browser: &'static str,
    /// Directory relative to the person's home, not a live-profile path to open.
    pub home_relative_directory: &'static str,
    pub enabled: bool,
}

pub const HOST_MANIFEST_LOCATIONS: [BrowserManifestLocation; 4] = [
    BrowserManifestLocation {
        browser: "chrome",
        home_relative_directory: "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        enabled: true,
    },
    BrowserManifestLocation {
        browser: "brave",
        home_relative_directory:
            "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        enabled: false,
    },
    BrowserManifestLocation {
        browser: "edge",
        home_relative_directory: "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
        enabled: false,
    },
    BrowserManifestLocation {
        browser: "arc",
        home_relative_directory: "Library/Application Support/Arc/User Data/NativeMessagingHosts",
        enabled: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_chrome_has_an_enabled_manifest_destination() {
        let enabled: Vec<_> = HOST_MANIFEST_LOCATIONS
            .iter()
            .filter(|location| location.enabled)
            .map(|location| location.browser)
            .collect();
        assert_eq!(enabled, ["chrome"]);
        assert!(HOST_MANIFEST_LOCATIONS
            .iter()
            .all(|location| !std::path::Path::new(location.home_relative_directory).is_absolute()));
    }
}
