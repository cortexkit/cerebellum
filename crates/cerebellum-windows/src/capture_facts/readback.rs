use super::{DesktopFrame, WindowFrameMetadata};
use std::time::Instant;
use windows::core::{Error, Interface, Result};
use windows::Graphics::Capture::{Direct3D11CaptureFrame, Direct3D11CaptureFramePool};
use windows::Win32::Foundation::{E_INVALIDARG, E_UNEXPECTED, HMODULE};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::System::WinRT::Direct3D11::IDirect3DDxgiInterfaceAccess;

pub(super) fn next_frame(
    pool: &Direct3D11CaptureFramePool,
) -> Result<Option<Direct3D11CaptureFrame>> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: this is the projection's method with a writable out-pointer.
    // A successful non-null result transfers one owned COM reference.
    unsafe {
        (pool.vtable().TryGetNextFrame)(pool.as_raw(), &mut raw).ok()?;
        Ok((!raw.is_null()).then(|| Direct3D11CaptureFrame::from_raw(raw)))
    }
}

pub(super) fn device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let (mut device, mut context) = (None, None);
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }
    device.zip(context).ok_or_else(|| E_UNEXPECTED.into())
}

struct Mapped<'a>(&'a ID3D11DeviceContext, &'a ID3D11Texture2D);

impl Drop for Mapped<'_> {
    fn drop(&mut self) {
        unsafe { self.0.Unmap(self.1, 0) };
    }
}

pub(super) fn pixels(
    device: &ID3D11Device,
    context: &ID3D11DeviceContext,
    frame: &Direct3D11CaptureFrame,
    received_at: Instant,
) -> Result<DesktopFrame> {
    let size = frame.ContentSize()?;
    let (width, height) = (size.Width as u32, size.Height as u32);
    if size.Width <= 0 || size.Height <= 0 {
        return Err(E_INVALIDARG.into());
    }
    let source: ID3D11Texture2D = unsafe {
        frame
            .Surface()?
            .cast::<IDirect3DDxgiInterfaceAccess>()?
            .GetInterface()?
    };
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { source.GetDesc(&mut desc) };
    if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || width > desc.Width || height > desc.Height {
        return Err(E_UNEXPECTED.into());
    }
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.MiscFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
    let mut staging = None;
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut staging))? };
    let staging = staging.ok_or_else(|| Error::from_hresult(E_UNEXPECTED))?;
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    unsafe {
        context.CopyResource(&staging, &source);
        context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
    }
    let _mapped = Mapped(context, &staging);
    let stride = mapped.RowPitch as usize;
    let row = width as usize * 4;
    if mapped.pData.is_null() || stride < row || stride > isize::MAX as usize / height as usize {
        return Err(E_UNEXPECTED.into());
    }
    let mut bgra = Vec::new();
    bgra.try_reserve_exact(row * height as usize)
        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
    for y in 0..height as usize {
        // SAFETY: mapping lives through this loop, its pitch covers each row,
        // and the content dimensions were checked against the texture extent.
        let bytes =
            unsafe { std::slice::from_raw_parts(mapped.pData.cast::<u8>().add(y * stride), row) };
        bgra.extend_from_slice(bytes);
    }
    Ok(DesktopFrame {
        info: WindowFrameMetadata {
            width,
            height,
            received_at,
        },
        bgra,
    })
}
