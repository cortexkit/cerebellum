/* Only the private test fixture links libjpeg. Read JPEG stdin, write RGB. */
#include <stdio.h>
#include <jpeglib.h>

int main(void) {
    struct jpeg_decompress_struct decoder;
    struct jpeg_error_mgr errors;
    decoder.err = jpeg_std_error(&errors);
    jpeg_create_decompress(&decoder);
    jpeg_stdio_src(&decoder, stdin);
    jpeg_read_header(&decoder, TRUE);
    decoder.out_color_space = JCS_RGB;
    jpeg_start_decompress(&decoder);
    printf("%u %u\n", decoder.output_width, decoder.output_height);
    JSAMPARRAY row = (*decoder.mem->alloc_sarray)((j_common_ptr)&decoder,
        JPOOL_IMAGE, decoder.output_width * 3, 1);
    while (decoder.output_scanline < decoder.output_height) {
        if (jpeg_read_scanlines(&decoder, row, 1) != 1 ||
            fwrite(row[0], 3, decoder.output_width, stdout) != decoder.output_width) {
            return 1;
        }
    }
    jpeg_finish_decompress(&decoder);
    jpeg_destroy_decompress(&decoder);
    return 0;
}
