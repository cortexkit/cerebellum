//! Window graphics capture and pixel-coordinate facts from Windows.

use std::time::{Duration, Instant};

use windows::core::{factory, Interface, Result};
use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
    IGraphicsCaptureSession2,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::{E_FAIL, E_NOINTERFACE, HWND};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::System::WinRT::Direct3D11::CreateDirect3D11DeviceFromDXGIDevice;
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, GetThreadDpiAwarenessContext, SetProcessDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowDisplayAffinity, IsIconic};

mod jpeg;
mod readback;
#[cfg(test)]
mod tests;

pub fn set_process_per_monitor_v2() {
    // An executable manifest or an earlier startup call can already have set
    // the context. Callers that depend on it read the effective context.
    let _ = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
}

pub fn per_monitor_v2() -> bool {
    unsafe {
        AreDpiAwarenessContextsEqual(
            GetThreadDpiAwarenessContext(),
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        )
        .as_bool()
    }
}

pub struct WindowCaptureProperties {
    pub minimized: bool,
    pub display_affinity: Option<u32>,
}

pub fn window_capture_properties(window: u32) -> WindowCaptureProperties {
    let hwnd = window as usize as windows_sys::Win32::Foundation::HWND;
    let mut affinity = 0;
    let read = unsafe { GetWindowDisplayAffinity(hwnd, &mut affinity) };
    WindowCaptureProperties {
        minimized: unsafe { IsIconic(hwnd) } != 0,
        display_affinity: (read != 0).then_some(affinity),
    }
}

struct Apartment;

impl Apartment {
    fn enter() -> Result<Self> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

pub fn capture_support() -> Option<bool> {
    let _apartment = Apartment::enter().ok()?;
    GraphicsCaptureSession::IsSupported().ok()
}

pub struct WindowFrameMetadata {
    pub width: u32,
    pub height: u32,
    pub received_at: Instant,
}

struct DesktopFrame {
    info: WindowFrameMetadata,
    bgra: Vec<u8>,
}

#[derive(Debug)]
pub enum FrameReadError {
    CursorPropertyMissing,
    Windows(windows::core::Error),
}

impl From<windows::core::Error> for FrameReadError {
    fn from(error: windows::core::Error) -> Self {
        Self::Windows(error)
    }
}

struct CaptureDevice(IDirect3DDevice);
struct FramePool(Direct3D11CaptureFramePool);
struct Session(GraphicsCaptureSession);

impl Drop for CaptureDevice {
    fn drop(&mut self) {
        let _ = self.0.Close();
    }
}

impl Drop for FramePool {
    fn drop(&mut self) {
        let _ = self.0.Close();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.0.Close();
    }
}

/// Read the first frame of a new HWND capture session, then encode it at the
/// size requested by the caller. No monitor capture or foreground operation
/// is involved. The caller owns window selection and whether to use the frame.
pub fn first_window_jpeg(
    window: u32,
    deadline: Instant,
    may_acquire: &dyn Fn() -> bool,
    size_for: impl FnOnce(&WindowFrameMetadata) -> Option<(u32, u32)>,
) -> std::result::Result<Option<Vec<u8>>, FrameReadError> {
    let _apartment = Apartment::enter()?;
    let Some(frame) = first_window_frame(window, deadline, may_acquire)? else {
        return Ok(None);
    };
    let Some((width, height)) = size_for(&frame.info) else {
        return Ok(None);
    };
    jpeg::encode(&frame, width, height)
        .map(Some)
        .map_err(Into::into)
}

fn first_window_frame(
    window: u32,
    deadline: Instant,
    may_acquire: &dyn Fn() -> bool,
) -> std::result::Result<Option<DesktopFrame>, FrameReadError> {
    if Instant::now() >= deadline || !may_acquire() {
        return Ok(None);
    }
    let interop = factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    let hwnd = HWND(window as usize as *mut core::ffi::c_void);
    let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(hwnd)? };
    let (device, context) = readback::device()?;
    let winrt_device = CaptureDevice(unsafe {
        CreateDirect3D11DeviceFromDXGIDevice(&device.cast::<IDXGIDevice>()?)?.cast()?
    });
    // Reverse declaration order closes the session, pool and WinRT device,
    // then releases the D3D context/device before the caller uninitializes WinRT.
    let pool = FramePool(Direct3D11CaptureFramePool::CreateFreeThreaded(
        &winrt_device.0,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        1,
        item.Size()?,
    )?);
    let session = Session(pool.0.CreateCaptureSession(&item)?);
    session.0.cast::<IGraphicsCaptureSession2>().map_err(|e| {
        if e.code() == E_NOINTERFACE {
            FrameReadError::CursorPropertyMissing
        } else {
            e.into()
        }
    })?;
    session.0.SetIsCursorCaptureEnabled(false)?;
    if session.0.IsCursorCaptureEnabled()? {
        return Err(windows::core::Error::from_hresult(E_FAIL).into());
    }
    if Instant::now() >= deadline || !may_acquire() {
        return Ok(None);
    }
    session.0.StartCapture()?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || !may_acquire() {
            return Ok(None);
        }
        // The WinRT projection signals a successful null interface as an
        // error. Get the nullable result without conflating it with HRESULTs.
        if let Some(frame) = readback::next_frame(&pool.0)? {
            let received_at = Instant::now();
            let result = if received_at < deadline && may_acquire() {
                readback::pixels(&device, &context, &frame, received_at).map(Some)
            } else {
                Ok(None)
            };
            let _ = frame.Close();
            return result.map_err(Into::into);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(4)));
    }
}
