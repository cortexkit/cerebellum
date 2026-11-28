use super::DesktopFrame;
use windows::core::{Error, Result};
use windows::Win32::Foundation::{E_INVALIDARG, E_UNEXPECTED, HGLOBAL};
use windows::Win32::Graphics::Imaging::{
    CLSID_WICImagingFactory, GUID_ContainerFormatJpeg, GUID_WICPixelFormat24bppBGR,
    GUID_WICPixelFormat32bppBGR, IWICImagingFactory, IWICPalette, WICBitmapDitherTypeNone,
    WICBitmapEncoderNoCache, WICBitmapInterpolationModeFant, WICBitmapPaletteTypeCustom,
};
use windows::Win32::System::Com::StructuredStorage::CreateStreamOnHGlobal;
use windows::Win32::System::Com::{
    CoCreateInstance, CLSCTX_INPROC_SERVER, STREAM_SEEK_END, STREAM_SEEK_SET,
};

pub(super) fn encode(source: &DesktopFrame, width: u32, height: u32) -> Result<Vec<u8>> {
    let stride = source.info.width.checked_mul(4).ok_or(E_INVALIDARG)?;
    if width == 0 || height == 0 || width > source.info.width || height > source.info.height {
        return Err(E_INVALIDARG.into());
    }
    // SAFETY: WinRT is initialized on this thread and every interface remains
    // live until the calls using it have returned. All buffers are owned here.
    unsafe {
        let factory: IWICImagingFactory =
            CoCreateInstance(&CLSID_WICImagingFactory, None, CLSCTX_INPROC_SERVER)?;
        // JPEG has no alpha. The D3D texture's fourth byte is not colour data.
        let bitmap = factory.CreateBitmapFromMemory(
            source.info.width,
            source.info.height,
            &GUID_WICPixelFormat32bppBGR,
            stride,
            &source.bgra,
        )?;
        let scaler = factory.CreateBitmapScaler()?;
        scaler.Initialize(&bitmap, width, height, WICBitmapInterpolationModeFant)?;
        let converter = factory.CreateFormatConverter()?;
        converter.Initialize(
            &scaler,
            &GUID_WICPixelFormat24bppBGR,
            WICBitmapDitherTypeNone,
            None::<&IWICPalette>,
            0.0,
            WICBitmapPaletteTypeCustom,
        )?;

        let stream = CreateStreamOnHGlobal(HGLOBAL::default(), true)?;
        let encoder = factory.CreateEncoder(&GUID_ContainerFormatJpeg, std::ptr::null())?;
        encoder.Initialize(&stream, WICBitmapEncoderNoCache)?;
        let mut frame = None;
        encoder.CreateNewFrame(&mut frame, std::ptr::null_mut())?;
        let frame = frame.ok_or(E_UNEXPECTED)?;
        frame.Initialize(None)?;
        frame.SetSize(width, height)?;
        let mut format = GUID_WICPixelFormat24bppBGR;
        frame.SetPixelFormat(&mut format)?;
        if format != GUID_WICPixelFormat24bppBGR {
            return Err(E_UNEXPECTED.into());
        }
        frame.WriteSource(&converter, std::ptr::null())?;
        frame.Commit()?;
        encoder.Commit()?;

        let mut length = 0;
        stream.Seek(0, STREAM_SEEK_END, Some(&mut length))?;
        stream.Seek(0, STREAM_SEEK_SET, None)?;
        let length = u32::try_from(length).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        let mut bytes = vec![0; length as usize];
        let mut read = 0;
        stream
            .Read(bytes.as_mut_ptr().cast(), length, Some(&mut read))
            .ok()?;
        if read != length {
            return Err(E_UNEXPECTED.into());
        }
        Ok(bytes)
    }
}
